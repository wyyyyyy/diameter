package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"os"
	"strconv"
)

func main() {
	// 定义 -p 参数，默认端口 3868
	port := flag.Int("p", 3868, "port to listen on")
	flag.Parse()
	log.SetPrefix(" [Diameter] ")
	err := LoadConfig("config.json")
	if err != nil {
		log.Fatalf("Load config failed: %v", err)
	}

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

// 单个会话处理
func handleConnection(conn net.Conn) {
	defer conn.Close()
	defer log.Printf("Connection from %v closed", conn.RemoteAddr())

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
		rsp, err := handleDiameter(&diameterMsg)
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

type DiameterHandler func(msg *DiameterMsg) (*DiameterMsg, error)

const (
	Cmd_CE   uint32 = 257      // Capabilities Exchange (CER/CEA)
	Cmd_DW   uint32 = 280      // Device Watchdog (DWR/DWA)
	Cmd_DP   uint32 = 282      // Disconnect Peer (DPR/DPA)
	Cmd_AC   uint32 = 265      // Accounting (ACR/ACA)
	Cmd_RA   uint32 = 258      // Re-Auth (RAR/RAA)
	Cmd_AS   uint32 = 274      // Abort Session (ASR/ASA)
	Cmd_CC   uint32 = 272      // Credit Control (CCR/CCA)
	Cmd_TEST uint32 = 16777214 // Credit Control (CCR/CCA)
)
const (
	// 成功类
	ResultCode_Success = 2001 // 请求成功完成

	// 协议错误类（Permanent Failures 5xxx）
	ResultCode_MissingAVP             = 5005 // 缺少必须的 AVP
	ResultCode_AVPUnsupported         = 5001 // 不支持的 AVP
	ResultCode_UnknownSessionID       = 5002 // 会话 ID 未知
	ResultCode_AuthenticationRejected = 4001 // 拒绝认证（常用于 AAA）

	// 应用错误类（Transient Failures 4xxx）
	ResultCode_UnableToComply = 5012 // 无法满足请求

	// 路由错误类
	ResultCode_UnableToDeliver            = 3002 // 无法路由此消息
	ResultCode_RealmNotServed             = 3003 // 域不受支持
	ResultCode_DestinationHostUnsupported = 3004

	// 命令类错误
	ResultCode_CommandUnsupported     = 3001 // 不支持的命令码
	ResultCode_ApplicationUnsupported = 3007 // 不支持的应用
)

var diameterHandlers = map[uint32]DiameterHandler{
	Cmd_CE: handleCER,  // Capability Exchange Request
	Cmd_DW: handleDWR,  // Device-Watchdog-Request
	Cmd_DP: handleDPR,  // Disconnect-Peer-Request
	Cmd_RA: handleTest, // 测试认证
}

func handleDiameter(msg *DiameterMsg) (*DiameterMsg, error) {
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
	return handler(msg)
}

// ///////////////////////////////////////////////////////////////////////////////////////

func handleCER(msg *DiameterMsg) (*DiameterMsg, error) {
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

func handleDWR(msg *DiameterMsg) (*DiameterMsg, error) {
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

func handleDPR(msg *DiameterMsg) (*DiameterMsg, error) {
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
	return rsp, errors.New("close connection")
}

func handleTest(msg *DiameterMsg) (*DiameterMsg, error) {
	return nil, fmt.Errorf("unsupport DiameterMsg AAR")
}

// ///////////////////////////////////////////////////////////////////////////////////////

type DiameterConfig struct {
	OriginHost    string            `json:"origin_host"`
	OriginRealm   string            `json:"origin_realm"`
	HostIPAddress string            `json:"host_ip_address"`
	ProductName   string            `json:"product_name"`
	CommandAppMap map[string]uint32 `json:"command_app_map"`
}

func (c *DiameterConfig) GetAppID(cmdID uint32) uint32 {
	key := strconv.FormatUint(uint64(cmdID), 10) // uint32转string
	appID := c.CommandAppMap[key]
	// 默认返回0
	return appID
}

var config DiameterConfig

func LoadConfig(path string) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()

	bytes, err := ioutil.ReadAll(file)
	if err != nil {
		return err
	}

	return json.Unmarshal(bytes, &config)
}
