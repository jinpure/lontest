// scanport project main.go
package main

import (
	//	"fmt"
	"log"
	"lontest"
	"time"

	"github.com/google/gopacket/pcap"
)

func main() {
	lontest.SetEntherNet("en1")
	// Open device
	handle, err := pcap.OpenLive("en1", 1024, false, 30*time.Second)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	//	UDPScanPort(lontest.DNSIP, handle)
	TCPScanPort(lontest.LonIP, handle)

}

func UDPScanPort(destHost string, handle *pcap.Handle) {

	var dstPort uint32
	for ; dstPort <= 65535; dstPort++ {
		time.Sleep(800 * time.Microsecond)
		pack, err := lontest.MAC_UDPPack(destHost, 10010, uint16(dstPort), []byte("xxx"))
		if err != nil {
			log.Fatal(err)

		}
		handle.WritePacketData(pack)
	}
}

func TCPScanPort(destHost string, handle *pcap.Handle) {
	var dstPort uint32
	for ; dstPort <= 65535; dstPort++ {
		time.Sleep(500 * time.Microsecond)
		pack := lontest.TCPSynPack(destHost, 10010, uint16(dstPort))
		handle.WritePacketData(pack)
	}
}
