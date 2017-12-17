// unreachable project main.go
package main

import (
	"flag"
	"fmt"
	"log"
	"lontest"
	"time"

	"github.com/google/gopacket/pcap"
)

func main() {

	net := flag.String("net", "en1", "the name of net interface")
	flag.Parse()
	lontest.SetEntherNet(*net)
	handle, err := pcap.OpenLive(lontest.EntherNet, 1600, false, 5*time.Second)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()
	unreachable, err := lontest.Unreachable(lontest.LonIP, 10, "161.202.139.108", 10008, lontest.HostUnreachable)
	if err != nil {
		log.Fatal(err)
	}
	vxlan, err := lontest.VxLanPack(lontest.VNI, unreachable)
	if err != nil {
		log.Fatal(err)
	}
	pkg, err := lontest.MAC_UDPPack(lontest.LonIP, 100, lontest.LonPort, vxlan)
	if err != nil {
		log.Fatal(err)
	}
	err = handle.WritePacketData(pkg)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("Hello World!")
}
