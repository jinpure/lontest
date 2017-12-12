// scanport project main.go
package main

import (
	"fmt"
	"os"
	//	"fmt"
	"log"
	"lontest"
	"time"

	"github.com/google/gopacket/pcap"
)

func main() {
	if len(os.Args) <= 1 {
		fmt.Println("need host")
		return
	}
	lontest.SetEntherNet("en1")
	// Open device
	handle, err := pcap.OpenLive("en1", 1024, false, 30*time.Second)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	UDPScanPort(os.Args[1], handle)
	//	TCPScanPort(lontest.BaiduIP, handle)

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

func TCPScanPort(destHost string, handle *pcap.Handle) error {
	var dstPort uint32
	for ; dstPort <= 65535; dstPort++ {
		time.Sleep(500 * time.Microsecond)
		pack, err := lontest.TCPSynPack(destHost, 10010, uint16(dstPort))
		if err != nil {
			log.Println(err)
			return err
		}
		handle.WritePacketData(pack)
	}

	return nil
}
