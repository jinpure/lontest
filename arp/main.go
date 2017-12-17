// arpbroadcast project main.go
package main

import (
	"flag"
	"log"
	"lontest"
	"time"

	"github.com/google/gopacket/pcap"
)

func main() {
	net := flag.String("net", "en1", "the name of net interface")
	flag.Parse()

	lontest.SetEntherNet(*net)

	handle, err := pcap.OpenLive(*net, 1500, false, 30*time.Second)
	if err != nil {
		log.Println(err)
		return
	}
	defer handle.Close()
	for {
		pack, err := lontest.ARPPack(lontest.XiaomiMAC, lontest.LonIP) //源IP为转发服务器IP
		if err != nil {
			log.Println(err)
			return
		}
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

		handle.WritePacketData(vxlanPack)
		time.Sleep(1 * time.Second)
	}
}
