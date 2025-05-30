package diameter

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net"
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
	dict, err = LoadDiameterMetaDictFromFile("dict.json")
	if err != nil {
		panic(err)
	}
}

var dict *DiameterMetaDict
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

type Session struct {
	ID        string
	NeedClose bool
	State     string
}

const (
	StateNew            = "New"            // 会话刚创建
	StateEstablished    = "Established"    // 握手完成，可正常处理业务
	StateAuthInProgress = "AuthInProgress" // 认证中
	StateAcctInProgress = "AcctInProgress" // 计费中
	StateClosing        = "Closing"        // 发起断开中
	StateClosed         = "Closed"         // 会话已关闭
)

type DiameterConfig struct {
	OriginHost         string            `json:"origin_host"`
	OriginRealm        string            `json:"origin_realm"`
	HostIPAddress      string            `json:"host_ip_address"`
	ProductName        string            `json:"product_name"`
	CommandAppMap      map[string]uint32 `json:"command_app_map"`
	UserID2passWD      map[string]string `json:"userid_2_password"`
	UserID2OauthToken  map[string]string `json:"userid_2_oauthtoken"`
	VendorID           uint32            `json:"vendor_id"`
	AuthApplicationIds []uint32          `json:"auth_application_ids"`
	AcctApplicationIds []uint32          `json:"acct_application_ids"`
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
	ResultCode_NoCommonApplication    = 5010 // 没有公共的认证、计费应用

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

func handleDiameter(session *Session, msg *DiameterMsg) (*DiameterMsg, error) {
	sessionAVP, _ := msg.FindAVPByCode(AVP_SessionId)
	if sessionAVP == nil {
		sessionAVP = NewAVPBuilder(AVP_SessionId, AVPFlag_Mandatory).SetStringData(generateSessionID(config.OriginHost)).Build()
	}
	rspBuilder := NewDiameterMsgBuilder().
		AddAVP(sessionAVP).
		SetCommandCode(msg.GetCommandCode()).
		SetAppID(msg.GetApplicationID()).
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
	// 解析CER并应用
	hostAVP, _ := msg.FindAVPByCode(AVP_OriginHost)
	realmAVP, _ := msg.FindAVPByCode(AVP_OriginRealm)
	log.Printf("%v域的主机%v 发起能力交换请求", realmAVP.GetStringData(), hostAVP.GetStringData())

	ipAVP, _ := msg.FindAVPByCode(AVP_HostIPAddress)
	log.Printf("%v域的主机%v ip地址为：%v", realmAVP.GetStringData(), hostAVP.GetStringData(), ipAVP.GetIPAddrData())
	vendorAVP, _ := msg.FindAVPByCode(AVP_VendorId)
	log.Printf("%v域的主机%v 厂商为：%v", realmAVP.GetStringData(), hostAVP.GetStringData(), dict.VendorMeta[strconv.Itoa(int(vendorAVP.GetIntData()))])
	productAVP, _ := msg.FindAVPByCode(AVP_ProductName)
	log.Printf("%v域的主机%v 产品名为：%v", realmAVP.GetStringData(), hostAVP.GetStringData(), productAVP.GetStringData())
	originStateAVP, _ := msg.FindAVPByCode(AVP_OriginStateId)
	log.Printf("%v域的主机%v 当前状态版本：%v", realmAVP.GetStringData(), hostAVP.GetStringData(), originStateAVP.GetIntData())

	supportedVendorAVPs := msg.FindAVPsByCode(AVP_SupportedVendorID)
	supportedVendorIDs := []uint32{}
	for _, avp := range supportedVendorAVPs {
		supportedVendorIDs = append(supportedVendorIDs, avp.GetIntData())
	}
	log.Printf("%v域的主机%v 支持的厂商为：%v",
		realmAVP.GetStringData(),
		hostAVP.GetStringData(),
		id2name(supportedVendorIDs, dict.VendorMeta))

	clientAuthAppAVPs := msg.FindAVPsByCode(AVP_AuthApplicationId)
	clientAuthAppIDs := []uint32{}
	msg.GetApplicationID()
	for _, appIDavp := range clientAuthAppAVPs {
		clientAuthAppIDs = append(clientAuthAppIDs, appIDavp.GetIntData())
	}
	log.Printf("%v域的主机%v 支持的认证应用为：%v",
		realmAVP.GetStringData(),
		hostAVP.GetStringData(),
		id2name(clientAuthAppIDs, dict.AuthAppMeta))
	clientAcctAppAVPs := msg.FindAVPsByCode(AVP_AcctApplicationId)
	clientAcctAppIDs := []uint32{}
	for _, appIDavp := range clientAcctAppAVPs {
		clientAcctAppIDs = append(clientAcctAppIDs, appIDavp.GetIntData())
	}
	log.Printf("%v域的主机%v 支持的计费应用为：%v",
		realmAVP.GetStringData(),
		hostAVP.GetStringData(),
		id2name(clientAcctAppIDs, dict.AcctAppMeta))

	shareAuthAppIDs := intersect(clientAuthAppIDs, config.AuthApplicationIds)
	shareAuthAppNames := id2name(shareAuthAppIDs, dict.AuthAppMeta)
	shareAcctAppIDs := intersect(clientAcctAppIDs, config.AcctApplicationIds)
	shareAcctAppNames := id2name(shareAcctAppIDs, dict.AcctAppMeta)

	if len(shareAuthAppIDs) > 0 {
		log.Printf("%v域的主机%v 与本端共同支持的认证应用为: %v", realmAVP.GetStringData(), hostAVP.GetStringData(), shareAuthAppNames)
	}
	if len(shareAcctAppIDs) > 0 {
		log.Printf("%v域的主机%v 与本端共同支持的计费应用为: %v", realmAVP.GetStringData(), hostAVP.GetStringData(), shareAcctAppNames)
	}

	// 构造并发送 CEA
	builder := NewDiameterMsgBuilder().
		SetCommandCode(msg.GetCommandCode()).
		SetAppID(msg.GetApplicationID()).
		SetHopByHopID(msg.GetHopByHopID()).
		SetEndToEndID(msg.GetEndToEndID()).
		SetFlags(FlagResponse).
		AddAVP(NewAVPBuilder(AVP_OriginHost, AVPFlag_Mandatory).SetStringData(config.OriginHost).Build()).
		AddAVP(NewAVPBuilder(AVP_OriginRealm, AVPFlag_Mandatory).SetStringData(config.OriginRealm).Build()).
		AddAVP(NewAVPBuilder(AVP_HostIPAddress, AVPFlag_Mandatory).SetIpData(net.ParseIP(config.HostIPAddress)).Build()).
		AddAVP(NewAVPBuilder(AVP_VendorId, AVPFlag_Mandatory).SetIntData(config.VendorID).Build()).
		AddAVP(NewAVPBuilder(AVP_ProductName, AVPFlag_Mandatory).SetStringData(config.ProductName).Build())
	for _, appID := range config.AuthApplicationIds {
		builder.
			AddAVP(NewAVPBuilder(AVP_AuthApplicationId, AVPFlag_Mandatory).SetIntData(appID).Build())
	}
	for _, appID := range config.AcctApplicationIds {
		builder.
			AddAVP(NewAVPBuilder(AVP_AcctApplicationId, AVPFlag_Mandatory).SetIntData(appID).Build())
	}

	if len(shareAuthAppIDs) > 0 || len(shareAcctAppIDs) > 0 {
		session.State = StateEstablished
		builder.
			AddAVP(NewAVPBuilder(AVP_ResultCode, AVPFlag_Mandatory).SetIntData(ResultCode_Success).Build())
		log.Printf("%v域的主机%v 结束能力交换请求,与本端有共同支持的应用，接受对端，会话已建立", realmAVP.GetStringData(), hostAVP.GetStringData())
	} else {
		log.Printf("%v域的主机%v 结束能力交换请求,与本端无共同支持的应用，忽略对端", realmAVP.GetStringData(), hostAVP.GetStringData())
		builder.
			AddAVP(NewAVPBuilder(AVP_ResultCode, AVPFlag_Mandatory).SetIntData(ResultCode_NoCommonApplication).Build())
	}

	// 4. 构建消息（自动算总长）
	return builder.Build(), nil
}

// 保活
func handleDWR(session *Session, msg *DiameterMsg) (*DiameterMsg, error) {
	hostAVP, _ := msg.FindAVPByCode(AVP_OriginHost)
	realmAVP, _ := msg.FindAVPByCode(AVP_OriginRealm)
	log.Printf("%v域的主机%v 发起保活请求", realmAVP.GetStringData(), hostAVP.GetStringData())

	rspBuilder := NewDiameterMsgBuilder().
		SetCommandCode(msg.GetCommandCode()). // DWA 命令码
		SetAppID(msg.GetApplicationID()).
		SetFlags(FlagResponse).             // R标志，响应消息
		SetHopByHopID(msg.GetHopByHopID()). // 保持请求一致
		SetEndToEndID(msg.GetEndToEndID()).
		AddAVP(NewAVPBuilder(AVP_OriginHost, AVPFlag_Mandatory).SetStringData(config.OriginHost).Build()).
		AddAVP(NewAVPBuilder(AVP_OriginRealm, AVPFlag_Mandatory).SetStringData(config.OriginRealm).Build()).
		AddAVP(NewAVPBuilder(AVP_HostIPAddress, AVPFlag_Mandatory).SetIpData(net.ParseIP(config.HostIPAddress)).Build()).
		AddAVP(NewAVPBuilder(AVP_VendorId, AVPFlag_Mandatory).SetIntData(config.VendorID).Build()).
		AddAVP(NewAVPBuilder(AVP_ProductName, AVPFlag_Mandatory).SetStringData(config.ProductName).Build()).
		AddAVP(NewAVPBuilder(AVP_AuthApplicationId, AVPFlag_Mandatory).SetIntData(msg.GetApplicationID()).Build())

	if session.State != StateEstablished {
		log.Printf("%v域的主机%v 当前未建立会话，保活失败", realmAVP.GetStringData(), hostAVP.GetStringData())
		rspBuilder.AddAVP(NewAVPBuilder(AVP_ResultCode, AVPFlag_Mandatory).SetIntData(ResultCode_UnableToDeliver).Build())
		rspBuilder.AddAVP(NewAVPBuilder(AVP_ErrorMessage, AVPFlag_Mandatory).SetStringData("session not established, send CER first").Build())
	}
	log.Printf("%v域的主机%v 会话保活成功", realmAVP.GetStringData(), hostAVP.GetStringData())
	rspBuilder.AddAVP(NewAVPBuilder(AVP_ResultCode, AVPFlag_Mandatory).SetIntData(ResultCode_Success).Build())
	return rspBuilder.Build(), nil
}

// 关闭
func handleDPR(session *Session, msg *DiameterMsg) (*DiameterMsg, error) {
	hostAVP, _ := msg.FindAVPByCode(AVP_OriginHost)
	realmAVP, _ := msg.FindAVPByCode(AVP_OriginRealm)
	causeAVP, _ := msg.FindAVPByCode(AVP_DisconnectCause)
	log.Printf("%v域的主机%v 发起会话关闭请求,原因：%v", realmAVP.GetStringData(), hostAVP.GetStringData(), dict.CauseMeta[strconv.Itoa(int(causeAVP.GetIntData()))])

	// 构造并发送 DPA
	rsp := NewDiameterMsgBuilder().
		SetCommandCode(msg.GetCommandCode()). // DWA 命令码
		SetAppID(msg.GetApplicationID()).
		SetFlags(FlagResponse).
		SetHopByHopID(msg.GetHopByHopID()). // 保持请求一致
		SetEndToEndID(msg.GetEndToEndID()).
		AddAVP(NewAVPBuilder(AVP_OriginHost, AVPFlag_Mandatory).SetStringData(config.OriginHost).Build()).
		AddAVP(NewAVPBuilder(AVP_OriginRealm, AVPFlag_Mandatory).SetStringData(config.OriginRealm).Build()).
		AddAVP(NewAVPBuilder(AVP_ResultCode, AVPFlag_Mandatory).SetIntData(ResultCode_Success).Build()).
		AddAVP(NewAVPBuilder(AVP_HostIPAddress, AVPFlag_Mandatory).SetIpData(net.ParseIP(config.HostIPAddress)).Build()).
		AddAVP(NewAVPBuilder(AVP_VendorId, AVPFlag_Mandatory).SetIntData(config.VendorID).Build()).
		AddAVP(NewAVPBuilder(AVP_ProductName, AVPFlag_Mandatory).SetStringData(config.ProductName).Build()).
		AddAVP(NewAVPBuilder(AVP_AuthApplicationId, AVPFlag_Mandatory).SetIntData(msg.GetApplicationID()).Build()).
		Build()
	session.NeedClose = true
	session.State = StateClosing
	log.Printf("%v域的主机%v 会话已关闭", realmAVP.GetStringData(), hostAVP.GetStringData())
	return rsp, nil
}

func handleTest(session *Session, msg *DiameterMsg) (*DiameterMsg, error) {
	hostAVP, _ := msg.FindAVPByCode(AVP_OriginHost)
	realmAVP, _ := msg.FindAVPByCode(AVP_OriginRealm)
	log.Printf("%v域的主机%v 发起认证请求", realmAVP.GetStringData(), hostAVP.GetStringData())

	// 前面做了检查，这里确保会有，如果没有的话应该修复入口处检查的问题
	sessionAVP, _ := msg.FindAVPByCode(AVP_SessionId)

	rspBuilder := NewDiameterMsgBuilder().
		AddAVP(sessionAVP).
		SetCommandCode(msg.GetCommandCode()).
		SetAppID(msg.GetApplicationID()).
		SetFlags(FlagResponse).
		SetHopByHopID(msg.GetHopByHopID()).
		SetEndToEndID(msg.GetEndToEndID()).
		AddAVP(NewAVPBuilder(AVP_OriginHost, AVPFlag_Mandatory).SetStringData(config.OriginHost).Build()).
		AddAVP(NewAVPBuilder(AVP_OriginRealm, AVPFlag_Mandatory).SetStringData(config.OriginRealm).Build()).
		AddAVP(NewAVPBuilder(AVP_HostIPAddress, AVPFlag_Mandatory).SetIpData(net.ParseIP(config.HostIPAddress)).Build())

	if session.State != StateEstablished {
		rspBuilder.AddAVP(NewAVPBuilder(AVP_ResultCode, AVPFlag_Mandatory).SetIntData(ResultCode_UnableToDeliver).Build())
		rspBuilder.AddAVP(NewAVPBuilder(AVP_ErrorMessage, AVPFlag_Mandatory).SetStringData("session not established, send CER first").Build())
		return rspBuilder.Build(), nil
	}

	avpUserID, _ := msg.FindAVPByCode(AVP_UserName)
	avpPassWD, _ := msg.FindAVPByCode(AVP_UserPassword)
	//也是一样的入口处检查确保会有这来AVP，但是data长度没检查
	if avpUserID.GetDataLength() < 4 {
		rspBuilder.
			AddAVP(NewAVPBuilder(AVP_ResultCode, AVPFlag_Mandatory).SetIntData(ResultCode_AuthenticationRejected).Build()).
			AddAVP(NewAVPBuilder(AVP_ErrorMessage, AVPFlag_Mandatory).SetStringData("userID or passWD wrong").Build())
		return rspBuilder.Build(), nil
	}
	userID := avpUserID.GetIntData()
	reqPasswd := avpPassWD.GetStringData()

	log.Printf("%v域的主机%v 申请认证用户名:%v", realmAVP.GetStringData(), hostAVP.GetStringData(), userID)
	log.Printf("%v域的主机%v 申请认证密码:%v", realmAVP.GetStringData(), hostAVP.GetStringData(), reqPasswd)
	rspBuilder.AddAVP(avpUserID).AddAVP(avpPassWD)

	if passwd, ok := config.UserID2passWD[strconv.Itoa(int(userID))]; ok && reqPasswd == passwd {
		//验证通过，返回令牌
		authToken := config.UserID2OauthToken[strconv.Itoa(int(userID))]
		rspBuilder.
			AddAVP(NewAVPBuilder(AVP_ResultCode, AVPFlag_Mandatory).SetIntData(ResultCode_Success).Build()).
			AddAVP(NewAVPBuilder(AVP_EAPPayload, AVPFlag_Mandatory).SetStringData(authToken).Build())
		log.Printf("%v域的主机%v 认证通过，授予令牌:%v", realmAVP.GetStringData(), hostAVP.GetStringData(), authToken)
		return rspBuilder.Build(), nil
	} else {
		rspBuilder.
			AddAVP(NewAVPBuilder(AVP_ResultCode, AVPFlag_Mandatory).SetIntData(ResultCode_AuthenticationRejected).Build()).
			AddAVP(NewAVPBuilder(AVP_ErrorMessage, AVPFlag_Mandatory).SetStringData("userID or passWD wrong").Build())
		log.Printf("%v域的主机%v 认证不通过，用户名或密码错误", realmAVP.GetStringData(), hostAVP.GetStringData())
		return rspBuilder.Build(), nil
	}
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
	commmandMeta := dict.Commands[m.GetCommandCode()]
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
	commandMeta, ok := dict.Commands[d.GetCommandCode()]
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
	Commands    map[uint32]CommandMeta `json:"commands"`
	AVPs        map[uint32]AVPMeta     `json:"avps"`
	AuthAppMeta map[string]string      `json:"auth_app_meta"`
	AcctAppMeta map[string]string      `json:"acct_app_meta"`
	VendorMeta  map[string]string      `json:"vendor_meta"`
	CauseMeta   map[string]string      `json:"cause_meta"`
}

// 临时结构体，用于 JSON 反序列化（Command 里 AVPs 是二维数组）
// 因为JSON的map key只能是string，所以先用slice，后面转换为map
type diameterMetaDictRaw struct {
	Commands    []CommandMeta     `json:"commands"`
	AVPs        []AVPMeta         `json:"avps"`
	AuthAppMeta map[string]string `json:"auth_app_meta"`
	AcctAppMeta map[string]string `json:"acct_app_meta"`
	VendorMeta  map[string]string `json:"vendor_meta"`
	CauseMeta   map[string]string `json:"cause_meta"`
}

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
		Commands:    make(map[uint32]CommandMeta),
		AVPs:        make(map[uint32]AVPMeta),
		AuthAppMeta: raw.AuthAppMeta,
		AcctAppMeta: raw.AcctAppMeta,
		VendorMeta:  raw.VendorMeta,
		CauseMeta:   raw.CauseMeta,
	}

	for _, avp := range raw.AVPs {
		dict.AVPs[avp.Code] = avp
	}

	for _, cmd := range raw.Commands {
		dict.Commands[cmd.Code] = cmd
	}

	return dict, nil
}
