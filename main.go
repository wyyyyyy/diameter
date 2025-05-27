package main

import (
	"encoding/binary"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"os"
	"strconv"
	"time"
)

func main() {
	// 定义 -p 参数，默认端口 3868
	port := flag.Int("p", 3868, "port to listen on")
	flag.Parse()
	log.SetPrefix("Diameter")
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

	var diameterMsg DiameterMsg
	diameterMsg.body = make([]*AVPMsg, 0, 10)

	if _, err := io.ReadFull(conn, diameterMsg.head[:]); err != nil {
		log.Printf("read diameter header error: %v", err)
		return
	}
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
		log.Printf("avp length mismatch: read %d, expect %d", readBodyLen, bodyLen)
		return
	}

	// 处理diameterMsg
	handleDiameter(&diameterMsg)
}

/////////////////////////////////////////////////////////////////////////////////////////

type DiameterHandler func(msg *DiameterMsg) (*DiameterMsg, error)

const (
	Cmd_CE uint32 = 257 // Capabilities Exchange (CER/CEA)
	Cmd_DW uint32 = 280 // Device Watchdog (DWR/DWA)
	Cmd_DP uint32 = 282 // Disconnect Peer (DPR/DPA)
	Cmd_AC uint32 = 265 // Accounting (ACR/ACA)
	Cmd_RA uint32 = 258 // Re-Auth (RAR/RAA)
	Cmd_AS uint32 = 274 // Abort Session (ASR/ASA)
	Cmd_CC uint32 = 272 // Credit Control (CCR/CCA)
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
	Cmd_CE: handleCER, // Capability Exchange Request
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
	// TODO: 构造并发送 CEA
	builder := NewDiameterMsgBuilder()

	// 1. 设置CommandCode = 257 (CEA)
	builder.SetCommandCode(msg.GetCommandCode())

	// 2. 设置AppID，假设用Diameter Common Messages（0）
	builder.SetAppID(config.GetAppID(msg.GetCommandCode()))

	// 3. 添加必须的 AVP（示例中值均用空或简单字节代替）
	builder.
		AddAVP(NewAVPBuilder(AVP_OriginHost, AVPFlag_Mandatory).SetStringData(config.OriginHost).Build()).
		AddAVP(NewAVPBuilder(AVP_OriginRealm, AVPFlag_Mandatory).SetStringData(config.OriginRealm).Build()).
		AddAVP(NewAVPBuilder(AVP_ResultCode, AVPFlag_Mandatory).SetIntData(ResultCode_Success).Build()).
		AddAVP(NewAVPBuilder(AVP_HostIPAddress, AVPFlag_Mandatory).SetIpData(net.ParseIP(config.HostIPAddress)).Build()).
		AddAVP(NewAVPBuilder(AVP_ProductName, AVPFlag_Mandatory).SetStringData(config.ProductName).Build()).
		AddAVP(NewAVPBuilder(AVP_AuthApplicationId, AVPFlag_Mandatory).SetIntData(config.GetAppID(msg.GetCommandCode())).Build())

	// 4. 构建消息（自动算总长）
	return builder.Build(), nil
}

func handleDWR(msg *DiameterMsg) {
	log.Println("Handling CER")
	// TODO: 构造并发送 DWR
}
func handleDPR(msg *DiameterMsg) {
	log.Println("Handling CER")
	// TODO: 构造并发送 DPR
}

// ///////////////////////////////////////////////////////////////////////////////////////

type DiameterMsgBuilder struct {
	msg *DiameterMsg
}

func NewDiameterMsgBuilder() *DiameterMsgBuilder {
	return &DiameterMsgBuilder{
		msg: &DiameterMsg{
			body: make([]*AVPMsg, 0, 10),
		},
	}
}

func (b *DiameterMsgBuilder) SetCommandCode(code uint32) *DiameterMsgBuilder {
	// Diameter header: bytes 1~3 (index 1,2,3)存放命令码（24位）
	b.msg.head[1] = byte(code >> 16)
	b.msg.head[2] = byte(code >> 8)
	b.msg.head[3] = byte(code)
	return b
}

func (b *DiameterMsgBuilder) SetAppID(appID uint32) *DiameterMsgBuilder {
	// Diameter头部app id是 bytes 4~7 (index 4..7)
	b.msg.head[4] = byte(appID >> 24)
	b.msg.head[5] = byte(appID >> 16)
	b.msg.head[6] = byte(appID >> 8)
	b.msg.head[7] = byte(appID)
	return b
}

func (b *DiameterMsgBuilder) AddAVP(avp *AVPMsg) *DiameterMsgBuilder {
	b.msg.body = append(b.msg.body, avp)
	return b
}

func (b *DiameterMsgBuilder) Build() *DiameterMsg {
	// 这里可以计算总长度写入头部 length 字段 bytes 0~2 (24位)
	totalLen := 20
	for _, avp := range b.msg.body {
		totalLen += len(avp.head) + len(avp.other)
	}
	b.msg.head[0] = byte(totalLen >> 16)
	b.msg.head[1] = byte(totalLen >> 8)
	b.msg.head[2] = byte(totalLen)

	return b.msg
}

// ///////////////////////////////////////////////////////////////////////////////////////

type DiameterMsg struct {
	head [20]byte
	body []*AVPMsg
}

// Validate 验证Diameter头部是否合法
func (d *DiameterMsg) Validate() error {
	if d.GetVersion() != 1 {
		return fmt.Errorf("invalid Diameter version: %d", d.GetVersion())
	}
	length := d.GetMessageLength()
	if length < 20 {
		return fmt.Errorf("invalid message length: %d, must be >= 20", length)
	}
	// R-bit 检查：必须是请求
	if d.head[4]&0x80 == 0 {
		return fmt.Errorf("not a request message (R-bit not set)")
	}

	return nil
}

// 是否请求类型
func (d *DiameterMsg) IsRequest() bool {
	return d.head[4]&0x80 != 0
}

// 版本号（通常是1）
func (m *DiameterMsg) GetVersion() uint8 {
	return m.head[0]
}

// 消息长度（3字节）
func (m *DiameterMsg) GetMessageLength() uint32 {
	return uint32(m.head[1])<<16 | uint32(m.head[2])<<8 | uint32(m.head[3])
}

// Flags：请求、代理、中继等标志
func (m *DiameterMsg) GetFlags() uint8 {
	return m.head[4]
}

// Command Code（3字节）
func (m *DiameterMsg) GetCommandCode() uint32 {
	return uint32(m.head[5])<<16 | uint32(m.head[6])<<8 | uint32(m.head[7])
}

// Application ID（4字节）
func (m *DiameterMsg) GetApplicationID() uint32 {
	return binary.BigEndian.Uint32(m.head[8:12])
}

// Hop-by-Hop ID（4字节）
func (m *DiameterMsg) GetHopByHopID() uint32 {
	return binary.BigEndian.Uint32(m.head[12:16])
}

// End-to-End ID（4字节）
func (m *DiameterMsg) GetEndToEndID() uint32 {
	return binary.BigEndian.Uint32(m.head[16:20])
}

// 获取消息体长度
func (d *DiameterMsg) GetBodyLength() int {
	totalLen := d.GetMessageLength()
	const headerLen = 20
	return int(totalLen) - headerLen
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

// ///////////////////////////////////////////////////////////////////////////////////////

const (
	AVPFlag_VendorSpecific byte = 0x80 // Vendor-Specific flag
	AVPFlag_Mandatory      byte = 0x40 // Mandatory flag
	AVPFlag_Protected      byte = 0x20 // Protected flag
)

type AVPBuilder struct {
	code  uint32
	flags byte
	other []byte
}

func NewAVPBuilder(code uint32, flags byte) *AVPBuilder {
	var other []byte
	if flags&0x80 != 0 {
		other = make([]byte, 4) // Reserve 4 bytes for Vendor-ID
	} else {
		other = make([]byte, 0)
	}
	return &AVPBuilder{
		code:  code,
		flags: flags,
		other: other,
	}
}

func (b *AVPBuilder) SetVendorID(id uint32) *AVPBuilder {
	if b.flags&0x80 == 0 {
		panic("SetVendorID called, but V-bit not set in flags")
	}
	binary.BigEndian.PutUint32(b.other[0:4], id)
	return b
}

func (b *AVPBuilder) SetData(data []byte) *AVPBuilder {
	offset := 0
	if b.flags&0x80 != 0 {
		offset = 4
	}
	// 重置 other 为前缀 + 数据
	newOther := make([]byte, offset+len(data))
	copy(newOther, b.other[:offset])
	copy(newOther[offset:], data)
	b.other = newOther
	return b
}

func (b *AVPBuilder) Build() *AVPMsg {
	// 构造 AVP 头部：Code (4 bytes), Flags + Length (3 bytes), Reserved (1 byte)
	var head [8]byte
	binary.BigEndian.PutUint32(head[0:4], b.code)

	length := 8 + len(b.other)
	head[4] = b.flags
	head[5] = byte((length >> 16) & 0xFF)
	head[6] = byte((length >> 8) & 0xFF)
	head[7] = byte(length & 0xFF)

	// 补齐 padding 到 4 字节
	padded := b.other
	if rem := length % 4; rem != 0 {
		pad := make([]byte, 4-rem)
		padded = append(padded, pad...)
	}

	return &AVPMsg{
		head:  head,
		other: padded,
	}
}

func (b *AVPBuilder) SetStringData(s string) *AVPBuilder {
	b.SetData([]byte(s))
	return b
}

func (b *AVPBuilder) SetIntData(i uint32) *AVPBuilder {
	buf := make([]byte, 4)
	binary.BigEndian.PutUint32(buf, i)
	b.SetData(buf)
	return b
}

func (b *AVPBuilder) SetIpData(ip net.IP) *AVPBuilder {
	b.SetData(ip.To4()) // 只支持IPv4，或者根据长度判断IPv6
	return b
}

func (b *AVPBuilder) SetTimeData(t time.Time) *AVPBuilder {
	buf := make([]byte, 4)
	// Diameter时间戳一般是秒数，取Unix时间戳即可
	binary.BigEndian.PutUint32(buf, uint32(t.Unix()))
	b.SetData(buf)
	return b
}

// ///////////////////////////////////////////////////////////////////////////////////////
type AVPMsg struct {
	head  [8]byte
	other []byte
}

// 获取 AVP Code（4 字节）
func (a *AVPMsg) GetCode() uint32 {
	return uint32(a.head[0])<<24 | uint32(a.head[1])<<16 | uint32(a.head[2])<<8 | uint32(a.head[3])
}

// 获取 Flags（1 字节）
func (a *AVPMsg) GetFlags() uint8 {
	return a.head[4]
}

// 获取 AVP Length（3 字节）
func (a *AVPMsg) GetLength() uint32 {
	return uint32(a.head[5])<<16 | uint32(a.head[6])<<8 | uint32(a.head[7])
}

func (a *AVPMsg) HasVendorID() bool {
	return a.head[4]&0x80 != 0
}

// 返回 AVP 除去 header（8 or 12 字节）外剩下的长度，包括 vendor + data + padding
func (a *AVPMsg) GetOtherLen() int {
	totalLen := int(a.GetLength())
	headerLen := 8
	padding := (4 - (totalLen % 4)) % 4
	if a.HasVendorID() {
		headerLen = 12
	}
	return totalLen - headerLen + padding
}

// Validate 校验AVP头是否合法
func (a *AVPMsg) Validate() error {
	length := a.GetLength()
	if length < 8 {
		return fmt.Errorf("invalid AVP length %d, must be >= 8", length)
	}
	if a.HasVendorID() && length < 12 {
		return fmt.Errorf("invalid AVP length %d, with Vendor-ID must be >= 12", length)
	}
	// 你可以添加更多规则，比如Flags中保留位检查等
	return nil
}
