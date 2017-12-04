// lontest project lontest.go
package lontest

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	mrand "math/rand"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

const (
	LonIP     string = "121.201.58.246"
	BaiduIP   string = "119.75.216.20"
	USAIP     string = "161.202.139.107"
	DNSHost   string = "114.114.114.114"
	LonPort   uint16 = 4789
	appleMAC  string = "28:cf:e9:58:ad:83"
	huaweiMAC string = "8c:34:fd:ea:b4:aa"
	zteMAC    string = "64:13:6c:a2:84:b9"
	XiaomiMAC string = "78:11:dc:03:7e:a0"
	routerMAC string = zteMAC

	snapshot_len int32         = 1600
	VNI          uint32        = 998
	promiscuous  bool          = false
	timeout      time.Duration = 30 * time.Second
	filter       string        = "host 121.201.58.246"
	liveTimeout                = 30 * time.Second
)

var (
	device      string = "en1"
	myIP        net.IP
	myMAC       net.HardwareAddr
	options     gopacket.SerializeOptions = gopacket.SerializeOptions{true, true}
	PingPayload []byte
)

func init() {
	PingPayload = make([]byte, 48)
	for i := 0; i < 48; i++ {
		PingPayload[i] = byte(i + 8)
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

func VxLanPack(vin uint32, payload []byte) ([]byte, error) {
	vxlan := &layers.VXLAN{
		ValidIDFlag: true,
		VNI:         VNI,
	}
	buffer := gopacket.NewSerializeBuffer()
	err := gopacket.SerializeLayers(buffer, options, vxlan, gopacket.Payload(payload))
	if err != nil {
		log.Println(err)
		return nil, err
	}

	return buffer.Bytes(), nil
}

func VxLanPingPack(pingDst string, id, seq uint16, payload []byte) ([]byte, error) {
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
		SrcPort: layers.UDPPort(LonPort),
		DstPort: layers.UDPPort(LonPort),
	}
	udpLayer.SetNetworkLayerForChecksum(ipLayer)

	dstmac, _ := net.ParseMAC(routerMAC)

	etherLayer := &layers.Ethernet{
		SrcMAC:       myMAC,
		DstMAC:       dstmac,
		EthernetType: layers.EthernetTypeIPv4,
	}

	buffer := gopacket.NewSerializeBuffer()

	pingPlayload, err := PingPack(pingDst, id, seq, payload)
	if err != nil {
		log.Println(err)
		return nil, err
	}

	pingPack, err := VxLanPack(VNI, pingPlayload)
	if err != nil {
		log.Println(err)
		return nil, err
	}
	gopacket.SerializeLayers(buffer, options, etherLayer, ipLayer, udpLayer, gopacket.Payload(pingPack))

	return buffer.Bytes(), nil
}

func VxLanPing(pingDst string, id uint16, times uint32, payload []byte) error {

	handle, err := pcap.OpenLive(device, snapshot_len, promiscuous, timeout)
	if err != nil {
		return err
	}
	defer handle.Close()
	var seq uint32 = 1
	for ; seq <= times; seq++ {

		icmpPack, err := VxLanPingPack(pingDst, id, uint16(seq), payload)
		if err != nil {
			log.Println(err)
			return err
		}
		handle.WritePacketData(icmpPack)
	}
	return nil
}

func PingPack(pingDst string, id, seq uint16, payload []byte) ([]byte, error) {

	icmp := &layers.ICMPv4{
		TypeCode: layers.CreateICMPv4TypeCode(8, 0),
		Id:       id,
		Seq:      seq,
	}

	buffer := gopacket.NewSerializeBuffer()

	err := gopacket.SerializeLayers(buffer, options, icmp, gopacket.Payload(payload))
	if err != nil {
		log.Println(err)
		return nil, err
	}
	return MAC_IPPack(pingDst, layers.IPProtocolICMPv4, buffer.Bytes()), nil

}

func Ping(pingDst string, id uint16, times uint32, payload []byte) error {

	handle, err := pcap.OpenLive(device, snapshot_len, promiscuous, timeout)
	if err != nil {
		return err
	}
	defer handle.Close()
	var seq uint32 = 1
	for ; seq <= times; seq++ {

		icmpPack, err := PingPack(pingDst, id, uint16(seq), payload)
		if err != nil {
			log.Println(err)
			return err
		}
		handle.WritePacketData(icmpPack)
	}
	return nil
}

func DNSQueryPack(dnsHost, dn string) ([]byte, error) {
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

	ret, err := MAC_UDPPack(dnsHost, 53, 53, buffer.Bytes())
	if err != nil {
		log.Println(err)
	}
	return ret, err
}

func DNSQuery(dnsHost, dn string) error {
	handle, err := pcap.OpenLive(device, snapshot_len, promiscuous, timeout)
	if err != nil {
		log.Println(err)
		return err
	}
	defer handle.Close()
	pack, err := DNSQueryPack(dnsHost, dn)
	if err != nil {
		log.Println(err)
		return err
	}
	return handle.WritePacketData(pack)
}

func MAC_IPPack(dstIP string, protocol layers.IPProtocol, payload []byte) []byte {

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

func MAC_UDPPack(dstIP string, srcPort, dstPort uint16, payload []byte) ([]byte, error) {

	dstMAC, _ := net.ParseMAC(routerMAC)

	ipLayer := &layers.IPv4{
		SrcIP:    myIP,
		DstIP:    net.ParseIP(dstIP),
		Version:  4,
		IHL:      5,
		Protocol: layers.IPProtocolUDP,
		TTL:      64,
	}

	etherLayer := &layers.Ethernet{
		SrcMAC:       myMAC,
		DstMAC:       dstMAC,
		EthernetType: layers.EthernetTypeIPv4,
	}
	udp := &layers.UDP{
		SrcPort: layers.UDPPort(srcPort),
		DstPort: layers.UDPPort(dstPort),
	}
	udp.SetNetworkLayerForChecksum(ipLayer)
	buffer := gopacket.NewSerializeBuffer()

	err := gopacket.SerializeLayers(buffer, options, etherLayer, ipLayer, udp, gopacket.Payload(payload))
	if err != nil {
		log.Println(err)
		return nil, err
	}

	return buffer.Bytes(), nil
}

func IP_UDPPack(dstIP string, srcPort, dstPort uint16, payload []byte) []byte {

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

func VxLanDnsPack(dnsHost, dn string) ([]byte, error) {
	dnsPack, err := DNSQueryPack(dnsHost, dn)
	if err != nil {
		log.Println(err)
		return nil, err
	}
	vxlanPack, err := VxLanPack(VNI, dnsPack)
	if err != nil {
		log.Println(err)
		return nil, err
	}

	ret, err := MAC_UDPPack(LonIP, uint16(LonPort), uint16(LonPort), vxlanPack)
	if err != nil {
		log.Println(err)
	}
	return ret, err
}
func VxLanDNS(dnsHost, dn string) error {

	handle, err := pcap.OpenLive(device, snapshot_len, promiscuous, timeout)
	if err != nil {
		log.Println(err)
		return err
	}
	defer handle.Close()
	pack, err := VxLanDnsPack(dnsHost, dn)
	if err != nil {
		log.Println(err)
		return err
	}
	err = handle.WritePacketData(pack)
	if err != nil {
		log.Println(err)
		return err
	}

	return nil
}

func TCPSynPack(dstIP string, srcPort, dstPort uint16) []byte {

	var mss uint16 = 1460
	mssOptData := make([]byte, 2)
	mssOptData[0] = byte(mss >> 8)
	mssOptData[1] = byte(mss)
	mssOpt := layers.TCPOption{
		OptionType:   2,
		OptionLength: 4,
		OptionData:   mssOptData,
	}
	noOpOpt := layers.TCPOption{
		OptionType: 1,
	}
	wsOpt := layers.TCPOption{
		OptionType:   3,
		OptionLength: 3,
		OptionData:   []byte{5},
	}
	var tsBuf bytes.Buffer
	binary.Write(&tsBuf, binary.BigEndian, uint32(time.Now().UnixNano()/1000000))
	binary.Write(&tsBuf, binary.BigEndian, uint32(0))
	tsOpt := layers.TCPOption{
		OptionType:   8,
		OptionLength: 10,
		OptionData:   tsBuf.Bytes(),
	}
	sackOpt := layers.TCPOption{
		OptionType:   4,
		OptionLength: 2,
	}
	eol := layers.TCPOption{
		OptionType: 0,
	}
	synTCP := &layers.TCP{
		SrcPort: layers.TCPPort(srcPort),
		DstPort: layers.TCPPort(dstPort),
		Seq:     100,
		SYN:     true,
		Window:  46635,
		Options: []layers.TCPOption{mssOpt, noOpOpt, wsOpt, noOpOpt, noOpOpt, tsOpt, sackOpt, eol},
	}

	dstMAC, _ := net.ParseMAC(routerMAC)

	ipLayer := &layers.IPv4{
		SrcIP:    myIP,
		DstIP:    net.ParseIP(dstIP),
		Version:  4,
		IHL:      5,
		Protocol: layers.IPProtocolTCP,
		TTL:      64,
	}

	etherLayer := &layers.Ethernet{
		SrcMAC:       myMAC,
		DstMAC:       dstMAC,
		EthernetType: layers.EthernetTypeIPv4,
	}

	synTCP.SetNetworkLayerForChecksum(ipLayer)
	buffer := gopacket.NewSerializeBuffer()
	gopacket.SerializeLayers(buffer, options, etherLayer, ipLayer, synTCP)
	return buffer.Bytes()
}

func ARPPack(srcMAC, srcIP string) ([]byte, error) {

	dstmac, _ := net.ParseMAC("00:00:00:00:00:00")
	srcmac, _ := net.ParseMAC(srcMAC)
	dstIP := make([]byte, 4) //随机目的IP
	srcProtAddress := []byte(net.ParseIP(srcIP))
	rand.Read(dstIP)
	arp := &layers.ARP{
		AddrType:          layers.LinkTypeEthernet,
		Protocol:          layers.EthernetTypeIPv4,
		HwAddressSize:     uint8(6),
		ProtAddressSize:   uint8(4),
		Operation:         uint16(1),
		SourceHwAddress:   srcmac,
		SourceProtAddress: srcProtAddress[len(srcIP)-4:],
		DstHwAddress:      dstmac,
		DstProtAddress:    dstIP,
	}

	etherLayer := &layers.Ethernet{
		SrcMAC:       srcmac,
		DstMAC:       net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		EthernetType: layers.EthernetTypeARP,
	}

	buffer := gopacket.NewSerializeBuffer()
	err := gopacket.SerializeLayers(buffer, options, etherLayer, arp)
	if err != nil {
		log.Println(err)
		return nil, err
	}
	return buffer.Bytes(), nil
}

func MAC_RandSrcIPPack(dstIP string, protocol layers.IPProtocol, payload []byte) []byte {

	dstMAC, _ := net.ParseMAC(routerMAC)
	myIP := make([]byte, 4)
	rand.Read(myIP)
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

func MAC_RandSrcIP_UDPPack(dstIP string, srcPort, dstPort uint16, payload []byte) []byte {

	udp := &layers.UDP{
		SrcPort: layers.UDPPort(srcPort),
		DstPort: layers.UDPPort(dstPort),
	}

	buffer := gopacket.NewSerializeBuffer()

	gopacket.SerializeLayers(buffer, options, udp, gopacket.Payload(payload))

	return MAC_RandSrcIPPack(dstIP, layers.IPProtocolUDP, buffer.Bytes())
}

func NestVxLan(deepth int, dstIP string, payload []byte) ([]byte, error) {

	if deepth == 1 {
		ret, err := VxLanPack(VNI, payload)
		if err != nil {
			log.Println(err)

		}
		return ret, err
	}

	nestPayload, err := NestVxLan(deepth-1, dstIP, payload)
	if err != nil {
		log.Println(err)
		return nil, err
	}

	vxlanPayload, err := MAC_UDPPack(dstIP, uint16(mrand.Int()), LonPort, nestPayload)
	if err != nil {
		log.Println(err)
		return nil, err
	}
	ret, err := VxLanPack(VNI, vxlanPayload)
	if err != nil {
		log.Println(err)
	}
	return ret, err
}

type PackTimer interface {
	Rtt(times int) (uint64, error)
}

func NewPacketTimer(timerType, dstHost string, port uint16) (PackTimer, error) {
	var timer PackTimer
	switch timerType {
	//	case "udpv4", "udp":
	//	case "tcpv4", "tcp":
	case "icmpv4", "icmp":
		timer = &ICMPv4Timer{
			Host: dstHost,
		}
	case "xicmpv4", "xicmp":
		icmp := &ICMPv4Timer{
			Host: dstHost,
		}
		timer = NewVxLanTimer(LonIP, icmp)
	default:
		return nil, errors.New("Unsupported timer type.")
	}

	return timer, nil
}

func NewVxLanTimer(xHost string, payload VxLanTimerPayload) *VxLanTimer {
	return &VxLanTimer{
		XHost:   xHost,
		Payload: payload,
	}
}

type ICMPv4Timer struct {
	Host    string
	id      uint16
	seq     uint16
	handle  *pcap.Handle
	lock    sync.Mutex
	rttChan chan uint64
}

func NewICMPv4Timer(host string) *ICMPv4Timer {
	return &ICMPv4Timer{
		Host: host,
	}
}

func (this *ICMPv4Timer) Rtt(times int) (uint64, error) {

	this.lock.Lock()
	defer this.lock.Unlock()

	this.id = uint16(mrand.Int())

	handle, err := pcap.OpenLive(device, snapshot_len, false, 5*time.Second)
	if err != nil {
		log.Println(err)
		return 0, err
	}
	this.handle = handle
	defer func() {
		this.handle.Close()
		this.handle = nil
	}()
	err = handle.SetBPFFilter(fmt.Sprintf("icmp && host %s ", this.Host))
	//	err = handle.SetBPFFilter(fmt.Sprintf("icmp"))
	if err != nil {
		log.Println(err)
		return 0, err
	}
	err = handle.SetDirection(pcap.DirectionIn)
	if err != nil {
		log.Println(err)
		return 0, err
	}
	if this.rttChan == nil {
		this.rttChan = make(chan uint64)
	}
	go this.capPack(times)

	this.injectPack(times)
	rtt := <-this.rttChan
	return rtt, nil

}

func (this *ICMPv4Timer) injectPack(times int) error {

	for seq := 1; seq <= times; seq++ {

		pingPack, err := this.Serialize()
		if err != nil {
			log.Println(err)
			return err
		}
		err = this.handle.WritePacketData(pingPack)
		if err != nil {
			log.Println(err)
			return err
		}
		time.Sleep(500 * time.Microsecond)
	}

	return nil

}

func (this *ICMPv4Timer) Serialize() ([]byte, error) {
	ts := &bytes.Buffer{}
	binary.Write(ts, binary.BigEndian, uint64(time.Now().UnixNano()/1000000))
	this.seq++
	log.Println("now:", ts)
	data, err := PingPack(this.Host, this.id, this.seq, ts.Bytes())
	if err != nil {
		log.Println(err)
		return nil, err
	}

	return data, err
}

func (this *ICMPv4Timer) DecodeTimestamp(data []byte) (int64, error) {
	var (
		eth       layers.Ethernet
		ip4       layers.IPv4
		icmp4     layers.ICMPv4
		timestamp gopacket.Payload
		err       error
	)
	parser := gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet, &eth, &ip4, &icmp4, &timestamp)
	parser.IgnoreUnsupported = true
	parser.IgnorePanic = true
	decoded := []gopacket.LayerType{}

	err = parser.DecodeLayers(data, &decoded)
	if err != nil {
		log.Println(err)
		return 0, err
	}
	if icmp4.Id != this.id {
		return 0, errors.New("not mine")
	}
	log.Println("timestamp", timestamp)
	return int64(binary.BigEndian.Uint64(timestamp)), nil
}

func (this *ICMPv4Timer) capPack(times int) (uint64, error) {

	var (
		rtt int64
	)

	packetSource := gopacket.NewPacketSource(this.handle, this.handle.LinkType())
	i := 0
	for packet := range packetSource.Packets() {

		ts, err := this.DecodeTimestamp(packet.Data())
		if err != nil {
			if err.Error() == "not mine" {
				continue
			}
			log.Println(err)
			return 0, err
		}
		capInfo := packet.Metadata().CaptureInfo
		log.Println("ts", ts)
		rtt += capInfo.Timestamp.UnixNano()/1000000 - ts
		i++
		if i == times {
			break
		}
	}
	ret := uint64(rtt / int64(times))
	this.rttChan <- ret
	return ret, nil
}

type TCPTimer struct {
	Host string
	Port uint16
}

type UDPTimer struct {
	Host string
	Port uint16
}

type VxLanTimer struct {
	VNI   uint32
	XHost string
	//	Host    string
	Payload VxLanTimerPayload
	conn    net.Conn
	lock    sync.Mutex
}

type VxLanTimerPayload interface {
	Serialize() ([]byte, error)
	DecodeTimestamp(data []byte) (int64, error)
}

func (this *VxLanTimer) Rtt(times int) (uint64, error) {

	this.lock.Lock()
	defer this.lock.Unlock()
	conn, err := net.Dial("udp", this.XHost)
	if err != nil {
		log.Println(err)
		return 0, err
	}
	this.conn = conn
	defer this.conn.Close()

	return 0, nil

}

func (this *VxLanTimer) send(times int) error {

	return nil
}

func (this *VxLanTimer) receive(time int) (uint64, error) {

	return 0, nil
}
