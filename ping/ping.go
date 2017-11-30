// ping project main.go
package main

import (
	"fmt"
	"net"
	pkg "networkpackage"
	"os"
	"syscall"
)

func main() {

	var (
		id, seq uint16
		addr    syscall.SockaddrInet4
		buffer  = make([]byte, 100)
	)

	sockFd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_ICMP)
	if err != nil {
		fmt.Println("Socket err:", err)
		return
	}
	//	os.Args[0]
	ipAddr, err := net.ResolveIPAddr("ip", os.Args[1])
	if err != nil {
		fmt.Println("ResolveIPAddr:", err)
		return
	}
	//	fmt.Println("ipAddr.IP:", ipAddr.IP)
	length := len(ipAddr.IP)
	addr.Addr[0] = ipAddr.IP[length-4]
	addr.Addr[1] = ipAddr.IP[length-3]
	addr.Addr[2] = ipAddr.IP[length-2]
	addr.Addr[3] = ipAddr.IP[length-1]
	//	fmt.Println(addr.Addr)
	seq = 100
	data := pkg.ICMP_EchoReq(id, seq, []byte("xxxxxx"))
	//	data := pkg.IPV4_NormalDatagram(0x00, 0, true, false, 65, pkg.IP_ICMP, srcIP, destIP, 0, icmp)
	fmt.Printf("data:%x\n", data)
	err = syscall.Sendto(sockFd, data, 0, &addr)
	if err != nil {
		fmt.Println("Sendto err:", err)
		return
	}
	n, _, err := syscall.Recvfrom(sockFd, buffer, 0)
	//	fmt.Println(buffer[:n])
	fmt.Println(string(buffer[28:n]))
}
