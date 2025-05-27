package main

import (
	"net"
)

func GetLocalIPv4() net.IP {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return net.ParseIP("127.0.0.1")
	}

	for _, addr := range addrs {
		ipNet, ok := addr.(*net.IPNet)
		if !ok || ipNet.IP.IsLoopback() {
			continue
		}

		ip := ipNet.IP.To4()
		if ip != nil {
			return ip
		}
	}

	// 如果没有找到合适的IPv4，返回回环地址
	return net.ParseIP("127.0.0.1")
}
