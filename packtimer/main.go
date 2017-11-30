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

	usage := fmt.Sprintf("usage:%s -protocol tcp|udp|icmp [-x use vxlan] -h HostIP -port dstport -d netdevice", os.Args[0])
	protocol := flag.String("protocol", "icmp", "tcp|udp|icmp")
	//	vxlan := flag.Bool("x", false, "use vxlan or not")
	dstHost := flag.String("h", "", "the destination host")
	device := flag.String("d", "en1", "the network device")
	port := flag.Int("port", 0, "the destination port")
	flag.Parse()
	if len(os.Args) == 1 {
		fmt.Println(usage)
		return
	}
	lontest.SetEntherNet(*device)

	packTimer, err := lontest.NewPacketTimer(*protocol, *dstHost, uint16(*port))
	if err != nil {
		log.Fatal(err)
	}

	rtt, err := packTimer.Rtt(10)
	if err != nil {
		log.Fatal(err)
	}
	log.Println("rtt:", rtt)
	return
}
