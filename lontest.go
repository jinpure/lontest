// lontest project lontest.go
package lontest

import (
	//	"bytes"
	"net"
	"time"

	"log"

	"strings"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

const (
	LonIP     string         = "121.201.58.246"
	BaiduIP   string         = "119.75.216.20"
	USAIP     string         = "161.202.139.108"
	LonPort   layers.UDPPort = 4789
	appleMAC  string         = "28:cf:e9:58:ad:83"
	huaweiMAC string         = "8c:34:fd:ea:b4:aa"
	zteMAC    string         = "64:13:6c:a2:84:b9"
	XiaomiMAC string         = "78:11:dc:03:7e:a0"
	routerMAC string         = XiaomiMAC

	snapshot_len int32  = 1024
	vni          uint32 = 998
	promiscuous  bool   = false
	//	err          error
	timeout time.Duration = 30 * time.Second
	//	handle  *pcap.Handle
	filter string = "host 121.201.58.246"
)

var (
	device      string = "en1"
	myIP        net.IP
	myMAC       net.HardwareAddr
	options     gopacket.SerializeOptions = gopacket.SerializeOptions{true, true}
	icmpPayload []byte
)

func init() {
	icmpPayload = make([]byte, 48)
	for i := 0; i < 48; i++ {
		icmpPayload[i] = byte(i + 8)
	}

	log.SetFlags(log.Ltime | log.Llongfile)
}

func SetEntherNet(dev string) {
	device = dev
	inface, err := net.InterfaceByName(dev)
	if err != nil {
		log.Fatalln(err)
	}
	addrs, err := inface.Addrs()
	if err != nil {
		log.Fatalln(err)
	}
	for _, addr := range addrs {
		if strings.Index(addr.String(), "192.168") >= 0 {
			myIP = net.ParseIP(strings.Split(addr.String(), "/")[0])
		}
	}
	myMAC = inface.HardwareAddr
}

func VxLanPkg(vin uint32, payload []byte) []byte {
	vxlan := &layers.VXLAN{
		ValidIDFlag: true,
		VNI:         vni,
	}
	buffer := gopacket.NewSerializeBuffer()
	gopacket.SerializeLayers(buffer, options, vxlan, gopacket.Payload(payload))

	return buffer.Bytes()
}

func VxLanPingPkg(pingDst string) ([]byte, error) {
	dstIP := net.ParseIP(LonIP)

	ipLayer := &layers.IPv4{
		SrcIP:    myIP,
		DstIP:    dstIP,
		Version:  4,
		IHL:      5,
		Protocol: layers.IPProtocolUDP,
		TTL:      65,
	}
	udpLayer := &layers.UDP{
		SrcPort: LonPort,
		DstPort: LonPort,
	}
	udpLayer.SetNetworkLayerForChecksum(ipLayer)

	dstmac, _ := net.ParseMAC(routerMAC)

	etherLayer := &layers.Ethernet{
		SrcMAC:       myMAC,
		DstMAC:       dstmac,
		EthernetType: layers.EthernetTypeIPv4,
	}

	buffer := gopacket.NewSerializeBuffer()

	pingPlayload := PingPkg(pingDst)
	//	if err != nil {
	//		log.Println(err)
	//		return nil, err
	//	}
	pingPkg := VxLanPkg(vni, pingPlayload)
	gopacket.SerializeLayers(buffer, options, etherLayer, ipLayer, udpLayer, gopacket.Payload(pingPkg))

	return buffer.Bytes(), nil
}

func VxLanPing(pingDst string) error {

	dstIP := net.ParseIP(LonIP)

	ipLayer := &layers.IPv4{
		SrcIP:    myIP,
		DstIP:    dstIP,
		Version:  4,
		IHL:      5,
		Protocol: layers.IPProtocolUDP,
		TTL:      65,
	}
	udpLayer := &layers.UDP{
		SrcPort: LonPort,
		DstPort: LonPort,
	}
	udpLayer.SetNetworkLayerForChecksum(ipLayer)

	dstmac, _ := net.ParseMAC(routerMAC)

	etherLayer := &layers.Ethernet{
		SrcMAC:       myMAC,
		DstMAC:       dstmac,
		EthernetType: layers.EthernetTypeIPv4,
	}

	buffer := gopacket.NewSerializeBuffer()

	pingPlayload := PingPkg(pingDst)
	pingPkg := VxLanPkg(vni, pingPlayload)
	gopacket.SerializeLayers(buffer, options, etherLayer, ipLayer, udpLayer, gopacket.Payload(pingPkg))

	handle, err := pcap.OpenLive(device, snapshot_len, promiscuous, timeout)
	if err != nil {
		log.Println(err)
		return err
	}

	handle.WritePacketData(buffer.Bytes())

	return nil
}

func PingPkg(pingDst string) []byte {

	icmp := &layers.ICMPv4{
		TypeCode: layers.CreateICMPv4TypeCode(8, 0),
		Id:       100,
		Seq:      1,
	}

	buffer := gopacket.NewSerializeBuffer()

	gopacket.SerializeLayers(buffer, options, icmp, gopacket.Payload(icmpPayload))
	return MAC_IPPkg(pingDst, layers.IPProtocolICMPv4, buffer.Bytes())

}

func Ping(pingDst string) error {

	//	buffer := gopacket.NewSerializeBuffer()
	payload := PingPkg(pingDst)
	//	if err != nil {
	//		log.Println(err)
	//		return err
	//	}
	//	gopacket.SerializeLayers(buffer, options, gopacket.Payload(payload))
	handle, err := pcap.OpenLive(device, snapshot_len, promiscuous, timeout)
	if err != nil {
		return err
	}
	handle.WritePacketData(payload)

	return nil
}

func DNSQueryPkg(dnsHost, dn string) []byte {
	dns := &layers.DNS{
		ID:      1,
		QR:      false,
		OpCode:  layers.DNSOpCodeQuery,
		RD:      true,
		QDCount: 1,
	}

	ques := make([]layers.DNSQuestion, 1)
	ques[0] = layers.DNSQuestion{
		Type:  layers.DNSTypeA,
		Class: layers.DNSClassIN,
	}

	ques[0].Name = []byte(dn)
	dns.Questions = ques

	buffer := gopacket.NewSerializeBuffer()
	gopacket.SerializeLayers(buffer, options, dns)

	return MAC_UDPPkg(dnsHost, 53, 53, buffer.Bytes())
	//	return IP_UDPPkg(dnsHost, 53, 53, buffer.Bytes())
}

func DNSQuery(dnsHost, dn string) error {
	handle, err := pcap.OpenLive(device, snapshot_len, promiscuous, timeout)
	if err != nil {
		log.Println(err)
		return err
	}
	pkg := DNSQueryPkg(dnsHost, dn)
	return handle.WritePacketData(pkg)
}

func MAC_IPPkg(dstIP string, protocol layers.IPProtocol, payload []byte) []byte {

	dstMAC, _ := net.ParseMAC(routerMAC)

	ipLayer := &layers.IPv4{
		SrcIP:    myIP,
		DstIP:    net.ParseIP(dstIP),
		Version:  4,
		IHL:      5,
		Protocol: protocol,
		TTL:      64,
	}

	etherLayer := &layers.Ethernet{
		SrcMAC:       myMAC,
		DstMAC:       dstMAC,
		EthernetType: layers.EthernetTypeIPv4,
	}

	buffer := gopacket.NewSerializeBuffer()
	gopacket.SerializeLayers(buffer, options, etherLayer, ipLayer, gopacket.Payload(payload))

	return buffer.Bytes()
}

func MAC_UDPPkg(dstIP string, srcPort, dstPort uint16, payload []byte) []byte {

	udp := &layers.UDP{
		SrcPort: layers.UDPPort(srcPort),
		DstPort: layers.UDPPort(dstPort),
	}

	buffer := gopacket.NewSerializeBuffer()

	gopacket.SerializeLayers(buffer, options, udp, gopacket.Payload(payload))

	return MAC_IPPkg(dstIP, layers.IPProtocolUDP, buffer.Bytes())
}

func IP_UDPPkg(dstIP string, srcPort, dstPort uint16, payload []byte) []byte {

	udp := &layers.UDP{
		SrcPort: layers.UDPPort(srcPort),
		DstPort: layers.UDPPort(dstPort),
	}
	ipLayer := &layers.IPv4{
		SrcIP:    myIP,
		DstIP:    net.ParseIP(dstIP),
		Version:  4,
		IHL:      5,
		Protocol: layers.IPProtocolUDP,
		TTL:      64,
	}
	buffer := gopacket.NewSerializeBuffer()
	gopacket.SerializeLayers(buffer, options, ipLayer, udp, gopacket.Payload(payload))

	return buffer.Bytes()
}

func VxLanDnsPkg(dnsHost, dn string) []byte {

	return MAC_UDPPkg(LonIP, uint16(LonPort), uint16(LonPort), VxLanPkg(vni, DNSQueryPkg(dnsHost, dn)))
	//return IP_UDPPkg(lonIP, uint16(lonPort), uint16(lonPort), VxLanPkg(vni, DNSQueryPkg(dnsHost, dn)))
}
func VxLanDNS(dnsHost, dn string) error {

	handle, err := pcap.OpenLive(device, snapshot_len, promiscuous, timeout)
	if err != nil {
		log.Println(err)
		return err
	}
	pkg := VxLanDnsPkg(dnsHost, dn)
	return handle.WritePacketData(pkg)
}

func TCPSynPkg(dstIP string, srcPort, dstPort uint16) []byte {

	synTCP := &layers.TCP{
		SrcPort: layers.TCPPort(srcPort),
		DstPort: layers.TCPPort(dstPort),
		Seq:     100,
		SYN:     true,
		ECE:     true,
		CWR:     true,
		//		ACK:     true,
		Window: 4096,
		//		Ack:    1,
	}
	buffer := gopacket.NewSerializeBuffer()
	gopacket.SerializeLayers(buffer, options, synTCP)
	return MAC_IPPkg(dstIP, layers.IPProtocolTCP, buffer.Bytes())
}

//func ARPPkg(srcMAC, srcIP, dstMAC, dstIP string) []byte {
//	dstmac, _ := net.ParseMAC(dstMAC)
//	srcmac, _ := net.ParseMAC(srcMAC)
//	arp := &layers.ARP{
//		AddrType:          layers.LinkTypeEthernet,
//		Protocol:          layers.EthernetTypeIPv4,
//		HwAddressSize:     6,
//		ProtAddressSize:   4,
//		Operation:         1,
//		SourceHwAddress:   srcmac,
//		SourceProtAddress: net.ParseIP(srcIP),
//		DstHwAddress:      dstmac,
//		DstProtAddress:    net.ParseIP(srcMAC),
//	}

//	routemac, _ := net.ParseMAC(routerMAC)

//	etherLayer := &layers.Ethernet{
//		SrcMAC:       myMAC,
//		DstMAC:       routemac,
//		EthernetType: layers.EthernetTypeARP,
//	}

//	buffer := gopacket.NewSerializeBuffer()
//	gopacket.SerializeLayers(buffer, options, etherLayer, arp)
//	return buffer.Bytes()
//}

func ARPBroadcastPkg(srcMAC, srcIP string) []byte {
	//	return ARPPkg(srcMAC, srcIP, "00:00:00:00:00:00", "0:0:0:0")

	dstmac, _ := net.ParseMAC("00:00:00:00:00:00")
	srcmac, _ := net.ParseMAC(srcMAC)
	arp := &layers.ARP{
		AddrType:          layers.LinkTypeEthernet,
		Protocol:          layers.EthernetTypeIPv4,
		HwAddressSize:     uint8(6),
		ProtAddressSize:   uint8(4),
		Operation:         uint16(1),
		SourceHwAddress:   srcmac,
		SourceProtAddress: []byte{121, 201, 58, 246},
		DstHwAddress:      dstmac,
		DstProtAddress:    []byte{219, 158, 11, 149},
	}

	//	routemac, _ := net.ParseMAC(routerMAC)
	// net.ParseMAC(XiaomiMAC)
	etherLayer := &layers.Ethernet{
		SrcMAC:       srcmac,
		DstMAC:       net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		EthernetType: layers.EthernetTypeARP,
	}

	buffer := gopacket.NewSerializeBuffer()
	gopacket.SerializeLayers(buffer, options, etherLayer, arp)
	return buffer.Bytes()
}
