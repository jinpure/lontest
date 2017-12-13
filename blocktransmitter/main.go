// blocktransmitter project main.go
package main

import (
	"fmt"
	"log"
	"lontest"
	"math/rand"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

func main() {
	handle, err := pcap.OpenLive("env", 1600, false, 5*time.Duration)
	if err != nil {
		log.Println(err)
		return
	}

	for {

		synPack, err := lontest.TCPSynPack("127.0.0.1", uint16(rand.Int()), 22)
		if err != nil {
			log.Println(err)
			return
		}

		vxlan, err := lontest.VxLanPack(lontest.VNI, synPack)
		if err != nil {
			log.Println(err)
			return
		}
		pkg, err := lontest.MAC_UDPPack(lontest.LonIP, lontest.LonPort, lontest.LonPort, vxlan)
		if err != nil {
			log.Println(err)
			return
		}

		err = handle.WritePacketData(pkg)
		if err != nil {
			log.Println(err)
			return
		}

		time.Sleep(1 * time.Millisecond)
	}
	//	fmt.Println("Hello World!")
}
