package main

import (
	"encoding/binary"
	"fmt"
)

type DiameterMsgBuilder struct {
	msg *DiameterMsg
}

const (
	FlagRequest  = 0x80
	FlagResponse = 0x00
	VendorIETF   = 0
)

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
	body []*AVPMsg
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
