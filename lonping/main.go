// lonping project main.go
package main

import (
	"flag"
	"fmt"
	"log"
	"lontest"
	"time"

	"github.com/google/gopacket/pcap"
)

const (
	usage = "usage:longping -h host -x use VxLan"
)

func main() {
	var vx = flag.Bool("x", false, "use VxLan")
	var host = flag.String("h", "", "host ip")
	flag.Parse()
	if *host == "" {
		fmt.Println(usage)
		return
	}
	lontest.SetEntherNet("en1")
	pingPack, err := lontest.PingPack(*host, 100, 1, lontest.PingPayload)
	if err != nil {
		log.Println(err)
		return
	}
	xPack, err := lontest.VxLanPack(lontest.VNI, pingPack)
	if err != nil {
		log.Println(err)
		return
	}

	vxlanPack, err := lontest.MAC_UDPPack(lontest.LonIP, uint16(lontest.LonPort), uint16(lontest.LonPort), xPack)
	if err != nil {
		log.Println(err)
		return
	}

	handle, err := pcap.OpenLive("en1", 1024, false, 30*time.Second)
	if err != nil {
		log.Println(err)
		return
	}

	if *vx {
		handle.WritePacketData(vxlanPack)
		return
	}
	handle.WritePacketData(pingPack)

}
