// packtimer project main.go
package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	//	"time"

	"lontest"

	_ "github.com/google/gopacket/pcap"
)

func main() {

	//	usage := fmt.Sprintf("usage:%s -protocol tcp|udp|icmp [-x use vxlan] -h HostIP -port dstport -d netdevice", os.Args[0])
	device := flag.String("n", "en1", "the name of net interface")
	protocol := flag.String("protocol", "icmp", "tcp|udp|icmp")
	dstHost := flag.String("h", "", "the destination host")
	port := flag.Int("port", 0, "the destination port")
	times := flag.Int("t", 10, "times")
	vxlan := flag.Bool("x", false, "use vxlan or not")
	flag.Parse()
	if len(os.Args) == 1 {
		flag.Usage()
		return
	}
	//	if *protocol == "udp" {
	//		*times = 65535
	//	}
	if *vxlan {
		*protocol = fmt.Sprint("x", *protocol)
	}
	lontest.SetEntherNet(*device)

	packTimer, err := lontest.NewPacketTimer(*protocol, *dstHost, uint16(*port))
	if err != nil {
		log.Fatal(err)
	}

	rtt, err := packTimer.Rtt(*times)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("average rtt:", rtt)
	return
}
