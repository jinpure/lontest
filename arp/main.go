// arpbroadcast project main.go
package main

import (
	//	"fmt"
	"lontest"
	"time"

	"log"

	"github.com/google/gopacket/pcap"
)

func main() {

	lontest.SetEntherNet("en1")
	pack, err := lontest.ARPPack(lontest.XiaomiMAC, lontest.LonIP) //源IP为转发服务器IP
	vx, err := lontest.VxLanPack(lontest.VNI, pack)
	if err != nil {
		log.Println(err)
		return
	}
	vxlanPack, err := lontest.MAC_UDPPack(lontest.LonIP, uint16(lontest.LonPort), uint16(lontest.LonPort), vx)
	if err != nil {
		log.Println(err)
		return
	}
	handle, err := pcap.OpenLive("en1", 1500, false, 30*time.Second)
	if err != nil {
		log.Println(err)
		return
	}

	for {

		handle.WritePacketData(vxlanPack)
		time.Sleep(1 * time.Second)
	}
}
