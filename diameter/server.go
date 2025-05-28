package diameter

import (
	"fmt"
	"io"
	"log"
	"net"
	"time"
)

func StartServer(port *int) {
	// 开始监听
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
	// 目前用不到，类似挑战-验证这种二阶段的认证需要用到。
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
