package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"strconv"
	"time"
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
	defer log.Printf("Closed Connection from %v", conn.RemoteAddr())
	log.Printf("Accepted connection from %v", conn.RemoteAddr())
	session := &Session{}
	for {
		var diameterMsg DiameterMsg
		diameterMsg.body = make([]*AVPMsg, 0, 10)
		// 客户端30s发一次保活，这里设置40s超时时间，需要考虑半包/空连接攻击
		conn.SetReadDeadline(time.Now().Add(40 * time.Second))
		if _, err := io.ReadFull(conn, diameterMsg.head[:]); err != nil {
			log.Printf("dropDiameter for read diameter header error: %v", err)
			return
		}
		// 已经收到报头的情况下，1s内收不完剩余数据，不属于正常情况，断开即可。
		conn.SetReadDeadline(time.Now().Add(1 * time.Second))
		if err := diameterMsg.Validate(); err != nil {
			log.Printf("dropDiameter for parse diameter header error: %v", err)
			return
		}

		bodyLen := diameterMsg.GetBodyLength()
		readBodyLen := 0

		for readBodyLen < bodyLen {
			var avpMsg AVPMsg

			if _, err := io.ReadFull(conn, avpMsg.head[:]); err != nil {
				log.Printf("dropDiameter for read avp header error: %v", err)
				return
			}
			readBodyLen += len(avpMsg.head)

			if err := avpMsg.Validate(); err != nil {
				log.Printf("dropDiameter for parse avp header error: %v", err)
				return
			}

			otherLen := avpMsg.GetOtherLen()
			avpMsg.other = make([]byte, otherLen)
			if readBodyLen+otherLen > bodyLen {
				log.Printf("dropDiameter for read more bytes than body length error: %d > %d", readBodyLen, bodyLen)
				return
			}
			if _, err := io.ReadFull(conn, avpMsg.other); err != nil {
				log.Printf("dropDiameter for read avp body error: %v", err)
				return
			}
			readBodyLen += otherLen
			diameterMsg.body = append(diameterMsg.body, &avpMsg)
		}

		if readBodyLen != bodyLen {
			log.Printf("dropDiameter for avp length mismatch error: read %d, expect %d", readBodyLen, bodyLen)
			return
		}

		// 处理diameterMsg，err是要断开连接的，不想断开连接的不要返回err，业务err在rsp中返回
		log.Printf("handleDiameter req:\n %s\n\n\n\n", diameterMsg.toString())
		rsp, err := handleDiameter(session, &diameterMsg)
		if rsp != nil {
			conn.Write(rsp.ToBytes())
			log.Printf("handleDiameter rsp:\n %s\n\n\n\n", rsp.toString())
		}
		if err != nil {
			log.Printf("handleDiameter err\n %v", err)
			return
		}
		if session.needClose {
			log.Print("handleDiameter finish\n")
			return
		}
	}
}

/////////////////////////////////////////////////////////////////////////////////////////

func handleDiameter(session *Session, msg *DiameterMsg) (*DiameterMsg, error) {
	sessionAVP, _ := msg.FindAVPByCode(AVP_SessionId)
	if sessionAVP == nil {
		sessionAVP = NewAVPBuilder(AVP_SessionId, AVPFlag_Mandatory).SetStringData(generateSessionID(config.OriginHost)).Build()
	}
	rspBuilder := NewDiameterMsgBuilder().
		AddAVP(sessionAVP).
		SetCommandCode(msg.GetCommandCode()).
		SetAppID(config.GetAppID(msg.GetCommandCode())).
		SetFlags(FlagResponse).
		SetHopByHopID(msg.GetHopByHopID()).
		SetEndToEndID(msg.GetEndToEndID()).
		AddAVP(NewAVPBuilder(AVP_OriginHost, AVPFlag_Mandatory).SetStringData(config.OriginHost).Build()).
		AddAVP(NewAVPBuilder(AVP_OriginRealm, AVPFlag_Mandatory).SetStringData(config.OriginRealm).Build()).
		AddAVP(NewAVPBuilder(AVP_HostIPAddress, AVPFlag_Mandatory).SetIpData(net.ParseIP(config.HostIPAddress)).Build())

	if err := msg.ValidateAVP(); err != nil {
		log.Printf("handleDiameter error for AVP missing: %v", err)
		rspBuilder.
			AddAVP(NewAVPBuilder(AVP_ResultCode, AVPFlag_Mandatory).SetIntData(ResultCode_MissingAVP).Build()).
			AddAVP(NewAVPBuilder(AVP_ErrorMessage, AVPFlag_Mandatory).SetStringData(err.Error()).Build())
		return rspBuilder.Build(), nil
	}

	cmdCode := msg.GetCommandCode()
	handler, exists := diameterHandlers[cmdCode]
	if !exists {
		log.Printf("unknown or unhandled command code: %d", cmdCode)
		err := fmt.Errorf("unknown or unhandled command %d: %d", ResultCode_CommandUnsupported, cmdCode)
		rspBuilder.
			AddAVP(NewAVPBuilder(AVP_ResultCode, AVPFlag_Mandatory).SetIntData(ResultCode_MissingAVP).Build()).
			AddAVP(NewAVPBuilder(AVP_ErrorMessage, AVPFlag_Mandatory).SetStringData(err.Error()).Build())
		return rspBuilder.Build(), err
	}
	return handler(session, msg)
}

// ///////////////////////////////////////////////////////////////////////////////////////

func handleCER(session *Session, msg *DiameterMsg) (*DiameterMsg, error) {
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
		AddAVP(NewAVPBuilder(AVP_VendorId, AVPFlag_Mandatory).SetIntData(config.VendorID).Build()).
		AddAVP(NewAVPBuilder(AVP_ProductName, AVPFlag_Mandatory).SetStringData(config.ProductName).Build()).
		AddAVP(NewAVPBuilder(AVP_AuthApplicationId, AVPFlag_Mandatory).SetIntData(config.GetAppID(msg.GetCommandCode())).Build())

	// 4. 构建消息（自动算总长）
	return builder.Build(), nil
}

func handleDWR(session *Session, msg *DiameterMsg) (*DiameterMsg, error) {
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
		AddAVP(NewAVPBuilder(AVP_VendorId, AVPFlag_Mandatory).SetIntData(config.VendorID).Build()).
		AddAVP(NewAVPBuilder(AVP_ProductName, AVPFlag_Mandatory).SetStringData(config.ProductName).Build()).
		AddAVP(NewAVPBuilder(AVP_AuthApplicationId, AVPFlag_Mandatory).SetIntData(config.GetAppID(msg.GetCommandCode())).Build()).
		Build()
	return rsp, nil
}

func handleDPR(session *Session, msg *DiameterMsg) (*DiameterMsg, error) {
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
		AddAVP(NewAVPBuilder(AVP_VendorId, AVPFlag_Mandatory).SetIntData(config.VendorID).Build()).
		AddAVP(NewAVPBuilder(AVP_ProductName, AVPFlag_Mandatory).SetStringData(config.ProductName).Build()).
		AddAVP(NewAVPBuilder(AVP_AuthApplicationId, AVPFlag_Mandatory).SetIntData(config.GetAppID(msg.GetCommandCode())).Build()).
		Build()
	session.needClose = true
	return rsp, nil
}

func handleTest(session *Session, msg *DiameterMsg) (*DiameterMsg, error) {
	// 前面做了检查，这里确保会有，如果没有的话应该修复入口处检查的问题
	sessionAVP, _ := msg.FindAVPByCode(AVP_SessionId)

	rspBuilder := NewDiameterMsgBuilder().
		AddAVP(sessionAVP).
		SetCommandCode(msg.GetCommandCode()).
		SetAppID(config.GetAppID(msg.GetCommandCode())).
		SetFlags(FlagResponse).
		SetHopByHopID(msg.GetHopByHopID()).
		SetEndToEndID(msg.GetEndToEndID()).
		AddAVP(NewAVPBuilder(AVP_OriginHost, AVPFlag_Mandatory).SetStringData(config.OriginHost).Build()).
		AddAVP(NewAVPBuilder(AVP_OriginRealm, AVPFlag_Mandatory).SetStringData(config.OriginRealm).Build()).
		AddAVP(NewAVPBuilder(AVP_HostIPAddress, AVPFlag_Mandatory).SetIpData(net.ParseIP(config.HostIPAddress)).Build())

	avpUserID, _ := msg.FindAVPByCode(AVP_UserName)
	avpPassWD, _ := msg.FindAVPByCode(AVP_UserPassword)
	//也是一样的入口处检查确保会有这来AVP

	userID := avpUserID.GetIntData()
	reqPasswd := avpPassWD.GetStringData()

	if passwd, ok := config.UserID2passWD[strconv.Itoa(int(userID))]; ok && reqPasswd == passwd {
		//验证通过，返回令牌
		rspBuilder.
			AddAVP(avpUserID).
			AddAVP(avpPassWD).
			AddAVP(NewAVPBuilder(AVP_ResultCode, AVPFlag_Mandatory).SetIntData(ResultCode_Success).Build()).
			AddAVP(NewAVPBuilder(AVP_EAPPayload, AVPFlag_Mandatory).SetStringData(config.UserID2OauthToken[strconv.Itoa(int(userID))]).Build())

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
	VendorID          uint32            `json:"vendor_id"` // 你可以加这个字段作为默认厂商ID
}

func (c *DiameterConfig) GetAppID(cmdID uint32) uint32 {
	key := strconv.FormatUint(uint64(cmdID), 10) // uint32转string
	appID := c.CommandAppMap[key]
	// 默认返回0
	return appID
}
