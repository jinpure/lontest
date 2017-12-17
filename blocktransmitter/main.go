// blocktransmitter project main.go
package main

import (
	"flag"
	"log"
	"lontest"
	"math/rand"
	"time"

	"github.com/google/gopacket/pcap"
)

func main() {
	net := flag.String("net", "en1", "the name of net interface")
	flag.Parse()
	lontest.SetEntherNet(*net)

	handle, err := pcap.OpenLive(*net, 1600, false, 5*time.Second)
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
