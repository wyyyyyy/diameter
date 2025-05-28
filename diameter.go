package main

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"time"
)

func init() {
	err := LoadConfig("config.json")
	if err != nil {
		log.Fatalf("Load config failed: %v", err)
	}
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

type DiameterMsgBuilder struct {
	msg *DiameterMsg
}

const (
	FlagRequest  = 0x80
	FlagResponse = 0x00
	VendorIETF   = 0
)

type DiameterHandler func(session *Session, msg *DiameterMsg) (*DiameterMsg, error)

const (
	Cmd_CE   uint32 = 257      // Capabilities Exchange (CER/CEA)
	Cmd_DW   uint32 = 280      // Device Watchdog (DWR/DWA)
	Cmd_DP   uint32 = 282      // Disconnect Peer (DPR/DPA)
	Cmd_AC   uint32 = 265      // Accounting (ACR/ACA)
	Cmd_RA   uint32 = 258      // Re-Auth (RAR/RAA)
	Cmd_AS   uint32 = 274      // Abort Session (ASR/ASA)
	Cmd_CC   uint32 = 272      // Credit Control (CCR/CCA)
	Cmd_TEST uint32 = 16777051 // Credit Control (CCR/CCA)
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
	Cmd_CE:   handleCER,  // Capability Exchange Request
	Cmd_DW:   handleDWR,  // Device-Watchdog-Request
	Cmd_DP:   handleDPR,  // Disconnect-Peer-Request
	Cmd_TEST: handleTest, // 测试认证
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
	b.msg.head[5] = byte(code >> 16)
	b.msg.head[6] = byte(code >> 8)
	b.msg.head[7] = byte(code)
	return b
}

func (b *DiameterMsgBuilder) SetAppID(appID uint32) *DiameterMsgBuilder {
	binary.BigEndian.PutUint32(b.msg.head[8:12], appID)
	return b
}

func (b *DiameterMsgBuilder) AddAVP(avp *AVPMsg) *DiameterMsgBuilder {
	b.msg.body = append(b.msg.body, avp)
	return b
}

func (b *DiameterMsgBuilder) SetHopByHopID(id uint32) *DiameterMsgBuilder {
	binary.BigEndian.PutUint32(b.msg.head[12:16], id)
	return b
}

func (b *DiameterMsgBuilder) SetEndToEndID(id uint32) *DiameterMsgBuilder {
	binary.BigEndian.PutUint32(b.msg.head[16:20], id)
	return b
}
func (b *DiameterMsgBuilder) SetFlags(flags byte) *DiameterMsgBuilder {
	b.msg.head[4] = flags
	return b
}
func (b *DiameterMsgBuilder) Build() *DiameterMsg {
	// 这里计算总长度写入头部 length 字段 bytes 1~3 (24位)
	totalLen := 20
	for _, avp := range b.msg.body {
		totalLen += avp.GetTotalLen()
	}
	b.msg.head[0] = 1
	b.msg.head[1] = byte(totalLen >> 16)
	b.msg.head[2] = byte(totalLen >> 8)
	b.msg.head[3] = byte(totalLen)

	return b.msg
}

// ///////////////////////////////////////////////////////////////////////////////////////

type DiameterMsg struct {
	head [20]byte
	// avp code 可能重复，式合法的，所以不能用map
	body []*AVPMsg
}

func generateSessionID(originHost string) string {
	now := time.Now()
	pid := os.Getpid()
	return fmt.Sprintf("%s;%d.%09d;%d", originHost, now.Unix(), now.Nanosecond(), pid)
}

func (m *DiameterMsg) FindAVPByCode(code uint32) *AVPMsg {
	for _, avp := range m.body {
		if avp.GetCode() == code {
			return avp
		}
	}
	return nil
}

func (m *DiameterMsg) FindAVPsByCode(code uint32) []*AVPMsg {
	var result []*AVPMsg
	for _, avp := range m.body {
		if avp.GetCode() == code {
			result = append(result, avp)
		}
	}
	return result
}

// Validate 验证Diameter头部是否合法
func (d *DiameterMsg) Validate() error {
	if d.GetVersion() != 1 {
		return fmt.Errorf("invalid Diameter version: %d", d.GetVersion())
	}
	length := d.GetMessageLength()
	if length < 20 || length > 10000 {
		return fmt.Errorf("invalid message length: %d, must be >= 20 <=10000", length)
	}
	// R-bit 检查：必须是请求
	if d.head[4]&FlagRequest == 0 {
		return fmt.Errorf("not a request message (R-bit not set)")
	}

	// 检查该带的AVP是不是都带了

	return nil
}

// 是否请求类型
func (d *DiameterMsg) IsRequest() bool {
	return d.head[4]&FlagRequest != 0
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

func (msg *DiameterMsg) ToBytes() []byte {
	totalLen := msg.GetMessageLength()
	buf := make([]byte, totalLen)
	copy(buf[:len(msg.head)], msg.head[:])

	offset := len(msg.head)
	for _, avp := range msg.body {
		copy(buf[offset:offset+avp.GetTotalLen()], avp.ToBytes())
		offset += avp.GetTotalLen()
	}
	return buf
}
