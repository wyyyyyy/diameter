package diameter

import (
	"fmt"
	"net"
	"strconv"
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

func slice2set(ids []uint32) map[uint32]struct{} {
	set := make(map[uint32]struct{}, len(ids))
	for _, id := range ids {
		set[id] = struct{}{}
	}
	return set
}

func id2name(ids []uint32, mapping map[string]string) []string {
	names := make([]string, 0, len(ids))
	for _, id := range ids {
		if name, ok := mapping[strconv.Itoa(int(id))]; ok {
			names = append(names, name)
		} else {
			// 如果没有映射，可以选择加个默认名，也可以跳过
			names = append(names, fmt.Sprintf("Unknown(%d)", id))
		}
	}
	return names
}

func intersect(a, b []uint32) []uint32 {
	set := make(map[uint32]struct{})
	for _, v := range a {
		set[v] = struct{}{}
	}
	result := make([]uint32, 0)
	seen := make(map[uint32]struct{}) // 防止重复加入
	for _, v := range b {
		if _, ok := set[v]; ok {
			if _, added := seen[v]; !added {
				result = append(result, v)
				seen[v] = struct{}{}
			}
		}
	}
	return result
}
