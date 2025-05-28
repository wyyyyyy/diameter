package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"strconv"
)

func main() {
	// 定义 -p 参数，默认端口 3868
	port := flag.Int("p", 3868, "port to listen on")
	flag.Parse()
	log.SetPrefix(" [Diameter] ")
	addr := fmt.Sprintf(":%d", *port)
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		log.Fatalf("Failed to listen on port %d: %v", *port, err)
	}
	defer ln.Close()
	log.Printf("Listening on port %d...", *port)

	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Printf("Accept error: %v", err)
			continue
		}
		log.Printf("Accepted connection from %v", conn.RemoteAddr())
		go handleConnection(conn)
	}
}

type Session struct {
	ID        string
	needClose bool
	// 其他字段...
}

// 单个会话处理
func handleConnection(conn net.Conn) {
	defer recover()
	defer conn.Close()
	defer log.Printf("Connection from %v closed", conn.RemoteAddr())
	session := &Session{}
	for {
		var diameterMsg DiameterMsg
		diameterMsg.body = make([]*AVPMsg, 0, 10)
		// 客户端30s发一次保活，这里设置40s超时时间，需要考虑半包/空连接攻击
		// conn.SetReadDeadline(time.Now().Add(40 * time.Second))
		if _, err := io.ReadFull(conn, diameterMsg.head[:]); err != nil {
			log.Printf("read diameter header error: %v", err)
			return
		}
		// 已经收到报头的情况下，1s内收不完剩余数据，不属于正常情况，断开即可。
		// conn.SetReadDeadline(time.Now().Add(1 * time.Second))
		if err := diameterMsg.Validate(); err != nil {
			log.Printf("parse diameter header error: %v", err)
			return
		}

		bodyLen := diameterMsg.GetBodyLength()
		readBodyLen := 0

		for readBodyLen < bodyLen {
			var avpMsg AVPMsg

			if _, err := io.ReadFull(conn, avpMsg.head[:]); err != nil {
				log.Printf("read avp header error: %v", err)
				return
			}
			readBodyLen += len(avpMsg.head)

			if err := avpMsg.Validate(); err != nil {
				log.Printf("parse avp header error: %v", err)
				return
			}

			otherLen := avpMsg.GetOtherLen()
			avpMsg.other = make([]byte, otherLen)
			if readBodyLen+otherLen > bodyLen {
				log.Printf("read more bytes than body length: %d > %d", readBodyLen, bodyLen)
				return
			}
			if _, err := io.ReadFull(conn, avpMsg.other); err != nil {
				log.Printf("read avp other error: %v", err)
				return
			}
			readBodyLen += otherLen
			diameterMsg.body = append(diameterMsg.body, &avpMsg)
		}

		if readBodyLen != bodyLen {
			log.Printf("avp length mismatch error: read %d, expect %d", readBodyLen, bodyLen)
			return
		}

		// 处理diameterMsg，err是要断开连接的，不想断开连接的不要返回err，业务err在rsp中返回
		rsp, err := handleDiameter(session, &diameterMsg)
		if rsp != nil {
			log.Printf("rsp bytes: % x\n", rsp.ToBytes())
			conn.Write(rsp.ToBytes())
		}
		if err != nil {
			log.Printf("handleDiameter error %v", err)
			return
		}
	}
}

/////////////////////////////////////////////////////////////////////////////////////////

func handleDiameter(session *Session, msg *DiameterMsg) (*DiameterMsg, error) {
	cmdCode := msg.GetCommandCode()
	handler, exists := diameterHandlers[cmdCode]
	if !exists {
		log.Printf("Unknown or unhandled command code: %d", cmdCode)
		response := NewDiameterMsgBuilder().
			SetCommandCode(cmdCode).
			SetAppID(msg.GetApplicationID()). // 如果有 AppID
			AddAVP(NewAVPBuilder(AVP_ResultCode, AVPFlag_Mandatory).SetIntData(ResultCode_CommandUnsupported).Build()).
			Build()
		return response, fmt.Errorf("%d: %d", ResultCode_CommandUnsupported, cmdCode)
	}
	return handler(session, msg)
}

// ///////////////////////////////////////////////////////////////////////////////////////

func handleCER(session *Session, msg *DiameterMsg) (*DiameterMsg, error) {
	log.Println("Handling CER")
	// 构造并发送 CEA
	builder := NewDiameterMsgBuilder().
		SetCommandCode(msg.GetCommandCode()).
		SetAppID(config.GetAppID(msg.GetCommandCode())).
		SetHopByHopID(msg.GetHopByHopID()).
		SetEndToEndID(msg.GetEndToEndID()).
		SetFlags(FlagResponse).
		AddAVP(NewAVPBuilder(AVP_OriginHost, AVPFlag_Mandatory).SetStringData(config.OriginHost).Build()).
		AddAVP(NewAVPBuilder(AVP_OriginRealm, AVPFlag_Mandatory).SetStringData(config.OriginRealm).Build()).
		AddAVP(NewAVPBuilder(AVP_ResultCode, AVPFlag_Mandatory).SetIntData(ResultCode_Success).Build()).
		AddAVP(NewAVPBuilder(AVP_HostIPAddress, AVPFlag_Mandatory).SetIpData(net.ParseIP(config.HostIPAddress)).Build()).
		AddAVP(NewAVPBuilder(AVP_VendorId, AVPFlag_Mandatory).SetIntData(VendorIETF).Build()).
		AddAVP(NewAVPBuilder(AVP_ProductName, AVPFlag_Mandatory).SetStringData(config.ProductName).Build()).
		AddAVP(NewAVPBuilder(AVP_AuthApplicationId, AVPFlag_Mandatory).SetIntData(config.GetAppID(msg.GetCommandCode())).Build())

	// 4. 构建消息（自动算总长）
	return builder.Build(), nil
}

func handleDWR(session *Session, msg *DiameterMsg) (*DiameterMsg, error) {
	log.Println("Handling DWR")

	rsp := NewDiameterMsgBuilder().
		SetCommandCode(msg.GetCommandCode()). // DWA 命令码
		SetAppID(config.GetAppID(msg.GetCommandCode())).
		SetFlags(FlagResponse).             // R标志，响应消息
		SetHopByHopID(msg.GetHopByHopID()). // 保持请求一致
		SetEndToEndID(msg.GetEndToEndID()).
		AddAVP(NewAVPBuilder(AVP_OriginHost, AVPFlag_Mandatory).SetStringData(config.OriginHost).Build()).
		AddAVP(NewAVPBuilder(AVP_OriginRealm, AVPFlag_Mandatory).SetStringData(config.OriginRealm).Build()).
		AddAVP(NewAVPBuilder(AVP_ResultCode, AVPFlag_Mandatory).SetIntData(ResultCode_Success).Build()).
		AddAVP(NewAVPBuilder(AVP_HostIPAddress, AVPFlag_Mandatory).SetIpData(net.ParseIP(config.HostIPAddress)).Build()).
		AddAVP(NewAVPBuilder(AVP_VendorId, AVPFlag_Mandatory).SetIntData(VendorIETF).Build()).
		AddAVP(NewAVPBuilder(AVP_ProductName, AVPFlag_Mandatory).SetStringData(config.ProductName).Build()).
		AddAVP(NewAVPBuilder(AVP_AuthApplicationId, AVPFlag_Mandatory).SetIntData(config.GetAppID(msg.GetCommandCode())).Build()).
		Build()
	return rsp, nil
}

func handleDPR(session *Session, msg *DiameterMsg) (*DiameterMsg, error) {
	log.Println("Handling DPR")
	// 构造并发送 DPA

	rsp := NewDiameterMsgBuilder().
		SetCommandCode(msg.GetCommandCode()). // DWA 命令码
		SetAppID(config.GetAppID(msg.GetCommandCode())).
		SetFlags(FlagResponse).
		SetHopByHopID(msg.GetHopByHopID()). // 保持请求一致
		SetEndToEndID(msg.GetEndToEndID()).
		AddAVP(NewAVPBuilder(AVP_OriginHost, AVPFlag_Mandatory).SetStringData(config.OriginHost).Build()).
		AddAVP(NewAVPBuilder(AVP_OriginRealm, AVPFlag_Mandatory).SetStringData(config.OriginRealm).Build()).
		AddAVP(NewAVPBuilder(AVP_ResultCode, AVPFlag_Mandatory).SetIntData(ResultCode_Success).Build()).
		AddAVP(NewAVPBuilder(AVP_HostIPAddress, AVPFlag_Mandatory).SetIpData(net.ParseIP(config.HostIPAddress)).Build()).
		AddAVP(NewAVPBuilder(AVP_VendorId, AVPFlag_Mandatory).SetIntData(VendorIETF).Build()).
		AddAVP(NewAVPBuilder(AVP_ProductName, AVPFlag_Mandatory).SetStringData(config.ProductName).Build()).
		AddAVP(NewAVPBuilder(AVP_AuthApplicationId, AVPFlag_Mandatory).SetIntData(config.GetAppID(msg.GetCommandCode())).Build()).
		Build()
	session.needClose = true
	return rsp, nil
}

func handleTest(session *Session, msg *DiameterMsg) (*DiameterMsg, error) {
	rspBuilder := NewDiameterMsgBuilder().
		SetCommandCode(msg.GetCommandCode()).
		SetAppID(config.GetAppID(msg.GetCommandCode())).
		SetFlags(FlagResponse).
		SetHopByHopID(msg.GetHopByHopID()).
		SetEndToEndID(msg.GetEndToEndID()).
		AddAVP(NewAVPBuilder(AVP_OriginHost, AVPFlag_Mandatory).SetStringData(config.OriginHost).Build()).
		AddAVP(NewAVPBuilder(AVP_OriginRealm, AVPFlag_Mandatory).SetStringData(config.OriginRealm).Build()).
		AddAVP(NewAVPBuilder(AVP_HostIPAddress, AVPFlag_Mandatory).SetIpData(net.ParseIP(config.HostIPAddress)).Build())
	sessionAVP := msg.FindAVPByCode(AVP_SessionId)
	if sessionAVP == nil {
		sessionID := generateSessionID(config.OriginHost)
		rspBuilder = rspBuilder.
			AddAVP(NewAVPBuilder(AVP_SessionId, AVPFlag_Mandatory).SetStringData(sessionID).Build()).
			AddAVP(NewAVPBuilder(AVP_ResultCode, AVPFlag_Mandatory).SetIntData(ResultCode_MissingAVP).Build()).
			AddAVP(NewAVPBuilder(AVP_ErrorMessage, AVPFlag_Mandatory).SetStringData("missing sessionID").Build())

		return rspBuilder.Build(), nil
	} else {
		rspBuilder.
			AddAVP(sessionAVP)
	}
	avpUserID := msg.FindAVPByCode(AVP_UserID)
	avpPassWD := msg.FindAVPByCode(AVP_UserPassword)
	if avpUserID == nil || avpPassWD == nil {
		rspBuilder.
			AddAVP(NewAVPBuilder(AVP_ResultCode, AVPFlag_Mandatory).SetIntData(ResultCode_MissingAVP).Build()).
			AddAVP(NewAVPBuilder(AVP_ErrorMessage, AVPFlag_Mandatory).SetStringData("missing userID or passWD").Build())
		return rspBuilder.Build(), nil
	}

	userID := avpUserID.GetIntData()
	reqPasswd := avpPassWD.GetStringData()

	if passwd, ok := config.UserID2passWD[strconv.Itoa(int(userID))]; ok && reqPasswd == passwd {
		//验证通过
		rspBuilder.
			AddAVP(NewAVPBuilder(AVP_ResultCode, AVPFlag_Mandatory).SetIntData(ResultCode_Success).Build()).
			AddAVP(NewAVPBuilder(AVP_AuthToken, AVPFlag_Mandatory).SetStringData(config.UserID2OauthToken[strconv.Itoa(int(userID))]).Build())

		return rspBuilder.Build(), nil
	} else {
		rspBuilder.
			AddAVP(NewAVPBuilder(AVP_ResultCode, AVPFlag_Mandatory).SetIntData(ResultCode_AuthenticationRejected).Build()).
			AddAVP(NewAVPBuilder(AVP_ErrorMessage, AVPFlag_Mandatory).SetStringData("userID or passWD wrong").Build())
		return rspBuilder.Build(), nil
	}
}

// ///////////////////////////////////////////////////////////////////////////////////////

type DiameterConfig struct {
	OriginHost        string            `json:"origin_host"`
	OriginRealm       string            `json:"origin_realm"`
	HostIPAddress     string            `json:"host_ip_address"`
	ProductName       string            `json:"product_name"`
	CommandAppMap     map[string]uint32 `json:"command_app_map"`
	UserID2passWD     map[string]string `json:"userid_2_password"`
	UserID2OauthToken map[string]string `json:"userid_2_oauthtoken"`
}

func (c *DiameterConfig) GetAppID(cmdID uint32) uint32 {
	key := strconv.FormatUint(uint64(cmdID), 10) // uint32转string
	appID := c.CommandAppMap[key]
	// 默认返回0
	return appID
}

var config DiameterConfig
