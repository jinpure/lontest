// nestvxlan project main.go
package main

//	"fmt"
import (
	"flag"
	"log"
	"lontest"
	"time"

	"github.com/google/gopacket/pcap"
)

func main() {
	net := flag.String("net", "en1", "the name of net interface")
	n := flag.Int("n", 3, "nest deepth")
	flag.Parse()
	lontest.SetEntherNet(*net)
	handle, err := pcap.OpenLive(*net, 1024, false, 30*time.Second)
	if err != nil {
		log.Println(err)
		return
	}

	pack, err := lontest.DNSQueryPack(lontest.DNSHost, "www.baidu.com")
	if err != nil {
		log.Fatal(err)
	}
	nestvxlan, err := lontest.NestVxLan(*n, lontest.LonIP, pack)
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
