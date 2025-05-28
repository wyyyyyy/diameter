package main

import (
	"encoding/binary"
	"fmt"
	"net"
	"strings"
	"time"
)

const (
	AVP_UserName              = 1
	AVP_UserPassword          = 2
	AVP_CHAPPassword          = 3
	AVP_NASIPAddress          = 4
	AVP_NASPort               = 5
	AVP_ServiceType           = 6
	AVP_FramedProtocol        = 7
	AVP_FramedIPAddress       = 8
	AVP_FramedIPNetmask       = 9
	AVP_FramedRouting         = 10
	AVP_FramedMTU             = 12
	AVP_FramedCompression     = 13
	AVP_LoginIPHost           = 14
	AVP_LoginService          = 15
	AVP_LoginTCPPort          = 16
	AVP_ReplyMessage          = 18
	AVP_ConnectionRequest     = 19
	AVP_ConnectionId          = 20
	AVP_OriginHost            = 264
	AVP_OriginRealm           = 296
	AVP_ResultCode            = 268
	AVP_DestinationHost       = 293
	AVP_DestinationRealm      = 283
	AVP_HostIPAddress         = 257
	AVP_ErrorMessage          = 281
	AVP_ErrorReportingHost    = 294
	AVP_SessionId             = 263
	AVP_OriginStateId         = 278
	AVP_TerminationCause      = 295
	AVP_AuthApplicationId     = 258
	AVP_VendorId              = 266
	AVP_ProductName           = 269
	AVP_SessionTimeout        = 27
	AVP_CalledStationId       = 30
	AVP_CallingStationId      = 31
	AVP_Class                 = 25
	AVP_State                 = 24
	AVP_ProxyInfo             = 284
	AVP_ProxyHost             = 280
	AVP_AuthorizationLifetime = 291
	AVP_RedirectHost          = 292
	AVP_FirmwareRevision      = 267
	AVP_Drmp                  = 278
	AVP_UserID                = 16777052
	AVP_EAPPayload            = 462
	// ...根据需要继续添加
)

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
	if flags&AVPFlag_VendorSpecific != 0 {
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
	if b.flags&AVPFlag_VendorSpecific == 0 {
		panic("SetVendorID called, but V-bit not set in flags")
	}
	binary.BigEndian.PutUint32(b.other[0:4], id)
	return b
}

func (b *AVPBuilder) SetData(data []byte) *AVPBuilder {
	offset := 0
	if b.flags&AVPFlag_VendorSpecific != 0 {
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
	b.SetData(append([]byte{0x00, 0x01}, ip.To4()...)) // 只支持IPv4，或者根据长度判断IPv6
	return b
}

func (b *AVPBuilder) SetTimeData(t time.Time) *AVPBuilder {
	buf := make([]byte, 4)
	// Diameter时间戳一般是秒数，取Unix时间戳即可
	binary.BigEndian.PutUint32(buf, uint32(t.Unix()))
	b.SetData(buf)
	return b
}

func GetStringData(data []byte) string {
	return string(data)
}

func GetIntData(data []byte) uint32 {
	if len(data) < 4 {
		return 0
	}
	return binary.BigEndian.Uint32(data)
}

func GetIpData(data []byte) net.IP {
	if len(data) < 6 {
		return nil
	}
	// 跳过前缀两字节（如 0x0001 表示 IPv4）
	return net.IP(data[2:6])
}

func GetTimeData(data []byte) time.Time {
	if len(data) < 4 {
		return time.Time{}
	}
	sec := binary.BigEndian.Uint32(data)
	return time.Unix(int64(sec), 0)
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

// 获取padding长度
func (a *AVPMsg) GetPaddingLength() int {
	length := int(a.GetLength())
	return (4 - (length % 4)) % 4
}

func (a *AVPMsg) HasVendorID() bool {
	return a.head[4]&AVPFlag_VendorSpecific != 0
}

func (a *AVPMsg) getOffset() int {
	if a.HasVendorID() {
		return 4 // 有 Vendor-ID，占 4 字节（Vendor-ID 是 uint32）
	}
	return 0
}

// GetRawData 返回原始data数据，不包含head，vendor-id
func (a *AVPMsg) GetRawData() []byte {
	offset := a.getOffset()
	end := len(a.other) - a.GetPaddingLength()
	return a.other[offset:end]
}

// GetIntData 将有效数据视为 uint32（大端）
func (a *AVPMsg) GetIntData() uint32 {
	data := a.GetRawData()
	return binary.BigEndian.Uint32(data[:4])
}

// GetStringData 将有效数据视为 UTF-8 字符串
func (a *AVPMsg) GetStringData() string {
	return string(a.GetRawData())
}

// GetTimeData 解析时间戳（4 字节秒数）
func (a *AVPMsg) GetTimeData() time.Time {
	data := a.GetRawData()
	if len(data) < 4 {
		return time.Time{} // 返回零时间
	}
	seconds := binary.BigEndian.Uint32(data[:4])
	return time.Unix(int64(seconds), 0)
}

func (a *AVPMsg) GetIPAddrData() net.IP {
	data := a.GetRawData()
	if len(data) < 6 {
		return nil
	}
	// 只支持 IPv4，前2字节类型应为0x0001
	if data[0] != 0x00 || data[1] != 0x01 {
		return nil
	}
	return net.IP(data[2:6])
}

// 返回 AVP 除去 header（header不包含vendor-id）外剩下的长度，包括 vendor-id + data + padding
func (a *AVPMsg) GetOtherLen() int {
	totalLen := int(a.GetLength())
	headerLen := 8
	padding := (4 - (totalLen % 4)) % 4
	return totalLen - headerLen + padding
}

func (a *AVPMsg) GetTotalLen() int {
	return a.GetOtherLen() + len(a.head)
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
	return nil
}
func (avp *AVPMsg) ToBytes() []byte {
	buf := make([]byte, len(avp.head)+len(avp.other))
	copy(buf[0:8], avp.head[:])
	copy(buf[8:], avp.other)
	return buf
}

func (avp *AVPMsg) ToString() string {
	var sb strings.Builder
	avpMeta := diameterDict.AVPs[avp.GetCode()]
	fmt.Fprintf(&sb, "AVP: %v(%v)  ", avpMeta.Name, avp.GetCode())
	fmt.Fprintf(&sb, "AVP-Flags: %v  ", avp.GetFlags())
	fmt.Fprintf(&sb, "AVP-Length: %v  ", avp.GetLength())
	typeStr := avpMeta.Type
	if typeStr == "UTF8String" || typeStr == "DiameterIdentity" {
		fmt.Fprintf(&sb, "AVP-Value: %v", avp.GetStringData())
	} else if typeStr == "Unsigned32" {
		fmt.Fprintf(&sb, "AVP-Value: %v", avp.GetIntData())
	} else if typeStr == "Address" {
		fmt.Fprintf(&sb, "AVP-Value: %v", avp.GetIPAddrData())
	}
	return sb.String()
}
