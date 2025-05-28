package main

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"strconv"
	"strings"
	"time"
)

func init() {
	err := LoadConfig("config.json")
	if err != nil {
		log.Fatalf("Load config failed: %v", err)
	}
	diameterDict, err = LoadDiameterMetaDictFromFile("dict.json")
	if err != nil {
		panic(err)
	}
}

var diameterDict *DiameterMetaDict
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

type DiameterConfig struct {
	OriginHost        string            `json:"origin_host"`
	OriginRealm       string            `json:"origin_realm"`
	HostIPAddress     string            `json:"host_ip_address"`
	ProductName       string            `json:"product_name"`
	CommandAppMap     map[string]uint32 `json:"command_app_map"`
	UserID2passWD     map[string]string `json:"userid_2_password"`
	UserID2OauthToken map[string]string `json:"userid_2_oauthtoken"`
	VendorID          uint32            `json:"vendor_id"` // 你可以加这个字段作为默认厂商ID
	AuthApplicationId uint32            `json:"auth_application_id"`
}

func (c *DiameterConfig) GetAppID(cmdID uint32) uint32 {
	key := strconv.FormatUint(uint64(cmdID), 10) // uint32转string
	appID := c.CommandAppMap[key]
	// 默认返回0
	return appID
}

type DiameterMsgBuilder struct {
	msg *DiameterMsg
}

const (
	FlagRequest  = 0x80
	FlagResponse = 0x00
)

type DiameterHandler func(session *Session, msg *DiameterMsg) (*DiameterMsg, error)

const (
	Cmd_CE   uint32 = 257    // Capabilities Exchange (CER/CEA)
	Cmd_DW   uint32 = 280    // Device Watchdog (DWR/DWA)
	Cmd_DP   uint32 = 282    // Disconnect Peer (DPR/DPA)
	Cmd_AC   uint32 = 265    // Accounting (ACR/ACA)
	Cmd_RA   uint32 = 258    // Re-Auth (RAR/RAA)
	Cmd_AS   uint32 = 274    // Abort Session (ASR/ASA)
	Cmd_CC   uint32 = 272    // Credit Control (CCR/CCA)
	Cmd_TEST uint32 = 234567 // Credit Control (CCR/CCA)
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

func (m *DiameterMsg) toString() string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "Version: %v  ", m.GetVersion())
	fmt.Fprintf(&sb, "Length: %v  ", m.GetMessageLength())
	fmt.Fprintf(&sb, "Flags: %v  ", m.GetFlags())
	commmandMeta := diameterDict.Commands[m.GetCommandCode()]
	fmt.Fprintf(&sb, "Command: %v(%v)  ", commmandMeta.Name, m.GetCommandCode())
	fmt.Fprintf(&sb, "ApplicationId: %v  ", m.GetApplicationID())
	fmt.Fprintf(&sb, "Hop-by-Hop: %v  ", m.GetHopByHopID())
	fmt.Fprintf(&sb, "End-to-End: %v  \n", m.GetEndToEndID())
	for _, avgMsg := range m.body {
		fmt.Fprintf(&sb, "%v\n", avgMsg.ToString())
	}
	return sb.String()
}

func generateSessionID(originHost string) string {
	now := time.Now()
	pid := os.Getpid()
	return fmt.Sprintf("%s;%d.%09d;%d", originHost, now.Unix(), now.Nanosecond(), pid)
}

func (m *DiameterMsg) FindAVPByCode(code uint32) (*AVPMsg, int) {
	for i, avp := range m.body {
		if avp.GetCode() == code {
			return avp, i
		}
	}
	return nil, -1
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
	return nil
}

// Validate 验证Diameter头部是否合法
func (d *DiameterMsg) ValidateAVP() error {

	// 检查该带的AVP是不是都带了，带多了没关系
	commandMeta, ok := diameterDict.Commands[d.GetCommandCode()]
	if !ok {
		return fmt.Errorf("command Not support")
	}
	for _, AVPCodes := range commandMeta.AVPCodes {
		atLeast1 := false
		for _, code := range AVPCodes {
			// avpMeta := diameterDict.AVPs[code]
			if avp, _ := d.FindAVPByCode(code); avp != nil {
				// 算了，不校验顺序了
				// if avpMeta.FixPos > 0 && avpMeta.FixPos != uint32(idx)+1 {
				// 	// 有固定位置且位置不对的，直接返回error
				// 	return fmt.Errorf("AVP was not in its fixed position %v actualPos %v needPos %v", code, idx+1, avpMeta.FixPos)
				// }
				atLeast1 = true
				break
			}
		}
		if !atLeast1 {
			return fmt.Errorf("miss avp, need one of %v", AVPCodes)
		}
	}
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

///////////////////////////////////////////////////////////////////////////////////////

type AVPMeta struct {
	Name   string `json:"name"`
	Code   uint32 `json:"code"`
	Type   string `json:"type"`
	FixPos uint32 `json:"fixPos"` // 新增字段，0 表示无固定位置
}

type CommandMeta struct {
	Name          string     `json:"name"`
	Code          uint32     `json:"code"`
	Request       bool       `json:"request"`
	ApplicationId uint32     `json:"application_id"`
	AVPCodes      [][]uint32 `json:"avps"` // 二维数组，子数组里至少有一个avp满足
}

type DiameterMetaDict struct {
	Commands map[uint32]CommandMeta `json:"commands"`
	AVPs     map[uint32]AVPMeta     `json:"avps"`
}

// 临时结构体，用于 JSON 反序列化（Command 里 AVPs 是二维数组）
// 因为JSON的map key只能是string，所以先用slice，后面转换为map
type diameterMetaDictRaw struct {
	Commands []CommandMeta `json:"commands"`
	AVPs     []AVPMeta     `json:"avps"`
}

// LoadDiameterMetaDictFromFile 从文件加载并转换成 DiameterMetaDict
func LoadDiameterMetaDictFromFile(filename string) (*DiameterMetaDict, error) {
	data, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("read file error: %w", err)
	}

	var raw diameterMetaDictRaw
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("json unmarshal error: %w", err)
	}

	dict := &DiameterMetaDict{
		Commands: make(map[uint32]CommandMeta),
		AVPs:     make(map[uint32]AVPMeta),
	}

	// AVP 转 map[code]AVPMeta
	for _, avp := range raw.AVPs {
		dict.AVPs[avp.Code] = avp
	}

	// Command 转 map[code]CommandMeta
	for _, cmd := range raw.Commands {
		dict.Commands[cmd.Code] = cmd
	}

	return dict, nil
}
