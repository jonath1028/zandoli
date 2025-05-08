package utils

import "net"

// IncIP increments an IP address by 1 (IPv4 or IPv6)
func IncIP(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

// IPsInSubnet returns a channel of IPs from a subnet, excluding a specific IP
func IPsInSubnet(subnet *net.IPNet, exclude net.IP) <-chan net.IP {
	ch := make(chan net.IP)
	go func() {
		defer close(ch)
		for ip := subnet.IP.Mask(subnet.Mask); subnet.Contains(ip); IncIP(ip) {
			tmp := make(net.IP, len(ip))
			copy(tmp, ip)
			if !tmp.Equal(exclude) {
				ch <- tmp
			}
		}
	}()
	return ch
}

