// nestvxlan project main.go
package main

//	"fmt"
import (
	"log"
	"lontest"
	"time"

	"github.com/google/gopacket/pcap"
)

func main() {
	handle, err := pcap.OpenLive("en1", 1024, false, 30*time.Second)
	if err != nil {
		log.Println(err)
		return
	}
	lontest.SetEntherNet("en1")
	pack, err := lontest.DNSQueryPack(lontest.DNSHost, "www.baidu.com")
	if err != nil {
		log.Fatal(err)
	}
	nestvxlan, err := lontest.NestVxLan(3, lontest.LonIP, pack)
	if err != nil {
		log.Fatal(err)
	}
	dnsPack, err := lontest.MAC_UDPPack(lontest.LonIP, lontest.LonPort, lontest.LonPort, nestvxlan)
	if err != nil {
		log.Fatal(err)
	}

	for {
		handle.WritePacketData(dnsPack)
		time.Sleep(400 * time.Microsecond)
	}
}
