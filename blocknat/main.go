// blocknat project main.go
package main

import (
	"flag"
	"log"
	"lontest"
	"time"

	"github.com/google/gopacket/pcap"
)

func main() {
	var port uint32
	net := flag.String("net", "en1", "the name of net interface")
	flag.Parse()

	lontest.SetEntherNet(*net)

	handle, err := pcap.OpenLive(*net, 1024, false, 30*time.Second)
	if err != nil {
		log.Println(err)
		return
	}
	dnsPack, err := lontest.DNSQueryPack(lontest.DNSHost, "www.baidu.com")
	if err != nil {
		log.Fatal(err)
	}
	xdnsPack, err := lontest.VxLanPack(lontest.VNI, dnsPack)
	if err != nil {
		log.Fatal(err)
	}

	for {

		for port = 0; port <= 65535; port++ {
			vxlanPack := lontest.MAC_RandSrcIP_UDPPack(lontest.LonIP, uint16(port), uint16(lontest.LonPort), xdnsPack)
			handle.WritePacketData(vxlanPack)
			time.Sleep(400 * time.Microsecond)
		}

		time.Sleep(400 * time.Microsecond)
	}
}
