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

	NetUnreachable      uint8 = 0
	HostUnreachable     uint8 = 1
	ProtocolUnreachable uint8 = 2
	PortUnreachable     uint8 = 3
)

var (
	EntherNet   string = "en1"
	myIP        net.IP
	myMAC       net.HardwareAddr
	options     gopacket.SerializeOptions = gopacket.SerializeOptions{true, true}
	PingPayload []byte

	ErrNoReply error = errors.New("No Reply")
)

func init() {
	PingPayload = make([]byte, 48)
	for i := 0; i < 48; i++ {
		PingPayload[i] = byte(i + 8)
	}

	log.SetFlags(log.Ltime | log.Llongfile)
}

func SetEntherNet(dev string) {
	EntherNet = dev
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

	handle, err := pcap.OpenLive(EntherNet, snapshot_len, promiscuous, timeout)
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

func Unreachable(srcHost string, srcPort uint16, dstHost string, dstPort uint16, code uint8) ([]byte, error) {

	udp := IP_UDPPack(dstHost, srcPort, dstPort, nil)

	icmp := &layers.ICMPv4{
		TypeCode: layers.CreateICMPv4TypeCode(8, code),
	}

	buffer := gopacket.NewSerializeBuffer()
	err := gopacket.SerializeLayers(buffer, options, icmp, gopacket.Payload(udp))
	if err != nil {
		log.Println(err)
		return nil, err
	}

	return buffer.Bytes(), nil
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

	handle, err := pcap.OpenLive(EntherNet, snapshot_len, promiscuous, timeout)
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
	handle, err := pcap.OpenLive(EntherNet, snapshot_len, promiscuous, timeout)
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

func IPPack(dstIP string, protocol layers.IPProtocol, payload []byte) []byte {

	//	dstMAC, _ := net.ParseMAC(routerMAC)

	ipLayer := &layers.IPv4{
		SrcIP:    myIP,
		DstIP:    net.ParseIP(dstIP),
		Version:  4,
		IHL:      5,
		Protocol: protocol,
		TTL:      64,
	}

	buffer := gopacket.NewSerializeBuffer()
	gopacket.SerializeLayers(buffer, options, ipLayer, gopacket.Payload(payload))

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

	handle, err := pcap.OpenLive(EntherNet, snapshot_len, promiscuous, timeout)
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

func TCPSynPack(dstIP string, srcPort, dstPort uint16) ([]byte, error) {

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
	now := time.Now()
	ts := midNightDuration(&now) / time.Millisecond //从午夜到当前时刻的毫秒数
	//	log.Println("sync ts:", ts)
	binary.Write(&tsBuf, binary.BigEndian, uint32(ts))
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
		Seq:     0,
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
	err := gopacket.SerializeLayers(buffer, options, etherLayer, ipLayer, synTCP)
	if err != nil {
		log.Println(err)
		return nil, err
	}
	return buffer.Bytes(), nil
}

func TCPResetPack(dstIP string, srcPort, dstPort uint16, seq uint32) ([]byte, error) {

	synTCP := &layers.TCP{
		SrcPort: layers.TCPPort(srcPort),
		DstPort: layers.TCPPort(dstPort),
		Seq:     seq,
		RST:     true,
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
	err := gopacket.SerializeLayers(buffer, options, etherLayer, ipLayer, synTCP)
	if err != nil {
		log.Println(err)
		return nil, err
	}
	return buffer.Bytes(), nil
}

func ARPPack(srcMAC, srcIP string) ([]byte, error) {

	dstmac, _ := net.ParseMAC("00:00:00:00:00:00")
	srcmac, _ := net.ParseMAC(srcMAC)
	dstIP := make([]byte, 4) //随机目的IP
	//	log.Println(srcIP)
	srcProtAddress := []byte(net.ParseIP(srcIP))
	//	log.Println(srcProtAddress)
	//	log.Println(srcProtAddress[len(srcProtAddress)-4:])
	rand.Read(dstIP)
	arp := &layers.ARP{
		AddrType:          layers.LinkTypeEthernet,
		Protocol:          layers.EthernetTypeIPv4,
		HwAddressSize:     uint8(6),
		ProtAddressSize:   uint8(4),
		Operation:         uint16(1),
		SourceHwAddress:   srcmac,
		SourceProtAddress: srcProtAddress[len(srcProtAddress)-4:],
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

func NewPacketTimer(timerType, dstHost string, dstPort uint16) (PackTimer, error) {

	var timer PackTimer
	switch timerType {
	case "udpv4", "udp":
		timer = NewUDPTimer(dstHost, dstPort)
	case "xudp":
		timer = NewVxLanTimer(LonIP, LonPort, NewUDPTimer(dstHost, dstPort))
		log.Println("xudp")
	case "tcpv4", "tcp":
		timer = NewTcpTimer(dstHost, dstPort)
	case "xtcp":
		timer = NewVxLanTimer(LonIP, LonPort, NewTcpTimer(dstHost, dstPort))

	case "icmpv4", "icmp":
		timer = NewICMPv4Timer(dstHost)
	case "xicmpv4", "xicmp":
		timer = NewVxLanTimer(LonIP, LonPort, NewICMPv4Timer(dstHost))
	default:
		return nil, errors.New("Unsupported timer type.")
	}

	return timer, nil
}

func NewVxLanTimer(xHost string, xPort uint16, payload VxLanTimerPayload) *VxLanTimer {
	return &VxLanTimer{
		XHost:   xHost,
		xPort:   xPort,
		Payload: payload,
		rttChan: make(chan uint64),
	}
}

type BaseTimer struct {
	lock          sync.Mutex
	ProtocolTimer ProtocolTimer
	handle        *pcap.Handle
	rttChan       chan uint64
	retRtt        uint64
	done          chan byte
	recvTimes     uint64
}

func (this *BaseTimer) Rtt(times int) (uint64, error) {

	this.lock.Lock()
	defer this.lock.Unlock()
	if this.rttChan == nil {
		this.rttChan = make(chan uint64, times)
	}
	if this.done == nil {
		this.done = make(chan byte)
	}
	handle, err := pcap.OpenLive(EntherNet, snapshot_len, false, 5*time.Second)
	if err != nil {
		log.Println(err)
		return 0, err
	}
	this.handle = handle
	defer func() {
		this.handle.Close()
		this.handle = nil
	}()

	err = handle.SetBPFFilter(this.ProtocolTimer.BPF())
	if err != nil {
		log.Println(err)
		return 0, err
	}
	err = handle.SetDirection(pcap.DirectionIn)
	if err != nil {
		log.Println(err)
		return 0, err
	}
	stopCap := make(chan byte, 1)
	rttChan := this.ProtocolTimer.CapPack(stopCap) //抓返回包goroutine
	go this.calcRtt(rttChan, times)                //累加RTT
	go func(times int, done chan byte) {           //发包goroutine
		for i := 1; i <= times; i++ {

			//			log.Println("i:", i)
			err = this.ProtocolTimer.SendPack()
			if err != nil {
				log.Println(err)
				return
			}

		}
		//		log.Println("done")
		done <- 0
	}(times, this.done)

	<-this.done //等待calcRtt、发包退出
	<-this.done
	stopCap <- 0 //通知抓包goroutine退出

	if this.recvTimes == 0 {
		return 0, ErrNoReply
	}
	return this.retRtt / this.recvTimes, nil //返回平均RTT值
}

func (this *BaseTimer) calcRtt(rttChan chan uint64, times int) {
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()
	for i := 1; i <= times; i++ {
		select {
		case rtt := <-rttChan:
			this.retRtt += rtt
			log.Println("rtt:", rtt)
			this.recvTimes++
		case <-ticker.C:
			break
		}
	}
	this.done <- 0
	log.Println("done")
}

type ProtocolTimer interface {
	//	Serialize() ([]byte, error)
	//	DecodeTimestamp([]byte) (uint64, error)
	BPF() string
	SendPack() error
	CapPack(stop chan byte) chan uint64
}

type ICMPv4Timer struct {
	BaseTimer
	Host string
	id   uint16
	seq  uint16
	//	handle *pcap.Handle
	//	lock   sync.Mutex
}

func NewICMPv4Timer(host string) *ICMPv4Timer {
	timer := &ICMPv4Timer{
		Host: host,
	}
	timer.BaseTimer.ProtocolTimer = timer

	return timer
}

func (this *ICMPv4Timer) SendPack() error {

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
	time.Sleep(time.Duration(uint16(mrand.Int())) * time.Microsecond)
	return nil

}

func (this *ICMPv4Timer) Serialize() ([]byte, error) {

	ts := &bytes.Buffer{}
	this.seq++
	now := time.Now()
	binary.Write(ts, binary.BigEndian, uint64(midNightDuration(&now).Nanoseconds())/1000000)
	data, err := PingPack(this.Host, this.id, this.seq, ts.Bytes())
	if err != nil {
		log.Println(err)
		return nil, err
	}

	return data, nil
}

func (this *ICMPv4Timer) BPF() string {
	return fmt.Sprintf("icmp && host %s ", this.Host)
}

func (this *ICMPv4Timer) DecodeTimestamp(data []byte) (uint64, error) {
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
		return 0, errors.New("Not mine")
	}
	//	log.Println("timestamp", timestamp)
	return binary.BigEndian.Uint64(timestamp), nil
}

func (this *ICMPv4Timer) CapPack(stop chan byte) chan uint64 {
	var (
		//		packet  gopacket.Packet
		err     error
		ts      uint64
		rttChan = make(chan uint64)
	)
	go func(stop chan byte) {
		packetSource := gopacket.NewPacketSource(this.handle, this.handle.LinkType())
		packets := packetSource.Packets()
		for {
			select {
			case packet := <-packets:

				if packet == nil {
					return
				}
				ts, err = this.DecodeTimestamp(packet.Data())
				if err != nil {

					log.Println(err)
					return
				}

				capInfo := packet.Metadata().CaptureInfo
				rtt := uint64(midNightDuration(&capInfo.Timestamp).Nanoseconds())/1000000 - ts
				rttChan <- rtt

			case <-stop:
				return
			}
		}
	}(stop)
	return rttChan
}

//返回t时刻到当天凌晨时间差
func midNightDuration(t *time.Time) time.Duration {

	midNight := time.Date(t.Year(), t.Month(), t.Day(), 0, 0, 0, 0, t.Location())
	return t.Sub(midNight)
}

type TCPTimer struct {
	BaseTimer
	DstHost       string
	DstPort       uint16
	srcPort       uint16
	lock          sync.Mutex
	timestampChan chan uint64
	syncChan      chan uint64
}

func NewTcpTimer(dstHost string, dstPort uint16) *TCPTimer {
	timer := &TCPTimer{
		DstHost:       dstHost,
		DstPort:       dstPort,
		syncChan:      make(chan uint64),
		timestampChan: make(chan uint64, 1),
	}

	timer.BaseTimer.ProtocolTimer = timer

	return timer

}

func (this *TCPTimer) sendReset() error {

	data, err := TCPResetPack(this.DstHost, this.srcPort, this.DstPort, 1)
	if err != nil {
		log.Println(err)
		return err
	}
	err = this.handle.WritePacketData(data)
	if err != nil {
		log.Println(err)
		return err
	}

	return nil
}

func (this *TCPTimer) SendPack() error {
	if this.syncChan == nil {
		this.syncChan = make(chan uint64)
	}
	this.srcPort = uint16(mrand.Int())
	data, err := this.Serialize()
	if err != nil {
		log.Println(err)
		return err
	}
	now := time.Now()
	sendTimestamp := uint64(midNightDuration(&now) / time.Millisecond)
	this.timestampChan <- sendTimestamp
	err = this.handle.WritePacketData(data)
	if err != nil {
		log.Println(err)
	}
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()
	select {
	case <-ticker.C:
		return nil
	case <-this.syncChan:
		err = this.sendReset()
		if err != nil {
			log.Println(err)
			return err
		}
	}

	return err
}

func (this *TCPTimer) CapPack(stopChan chan byte) chan uint64 {

	packetSource := gopacket.NewPacketSource(this.handle, this.handle.LinkType())
	packets := packetSource.Packets()
	rttChan := make(chan uint64)
	go func() {
		var (
			err error
			ts  uint64
		)
		for {
			select {
			case packet := <-packets:
				this.syncChan <- 0
				ts, err = this.DecodeTimestamp(packet.Data())
				if err != nil {
					if err.Error() == "Not mine" {
						continue
					} else {
						log.Println(err)
						return
					}
				}
				//				log.Println(uint64(midNightDuration(&packet.Metadata().CaptureInfo.Timestamp).Nanoseconds()) / 1000000)
				rtt := uint64(midNightDuration(&packet.Metadata().CaptureInfo.Timestamp).Nanoseconds())/1000000 - ts
				//				log.Println("rtt:", rtt)
				rttChan <- rtt
			case <-stopChan:
				return
			}
		}
	}()

	return rttChan

}

func (this *TCPTimer) Serialize() ([]byte, error) {

	return TCPSynPack(this.DstHost, this.srcPort, this.DstPort)

}

func (this *TCPTimer) BPF() string {
	return fmt.Sprintf("tcp && host %s ", this.DstHost)
}

func (this *TCPTimer) DecodeTimestamp(data []byte) (uint64, error) {

	var (
		eth     layers.Ethernet
		ip4     layers.IPv4
		tcp     layers.TCP
		payload gopacket.Payload
		err     error
	)
	sendTimestamp := <-this.timestampChan
	parser := gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet, &eth, &ip4, &tcp, &payload)
	parser.IgnoreUnsupported = true
	parser.IgnorePanic = true
	decoded := []gopacket.LayerType{}

	err = parser.DecodeLayers(data, &decoded)
	if err != nil {
		log.Println(err)
		return 0, err
	}
	if uint16(tcp.DstPort) != this.srcPort {
		return 0, errors.New("Not mine")
	}
	for _, opt := range tcp.Options {
		if opt.OptionType == 8 {
			ts := binary.BigEndian.Uint64(opt.OptionData)
			//			log.Println(ts >> 32)
			//			log.Println(uint32(ts))
			return ts & 0x00000000ffffffff, nil
		}
	}
	return sendTimestamp, nil
}

type UDPTimer struct {
	BaseTimer
	DstHost        string
	DstPort        uint16
	srcPort        uint16
	birthTimestamp time.Time
	syncChan       chan uint64
	timestampChan  chan uint64
}

func NewUDPTimer(dstHost string, dstPort uint16) *UDPTimer {

	timer := &UDPTimer{
		DstHost:       dstHost,
		DstPort:       dstPort,
		syncChan:      make(chan uint64),
		timestampChan: make(chan uint64, 1),
	}
	timer.BaseTimer.ProtocolTimer = timer
	return timer
}

func (this *UDPTimer) Serialize() ([]byte, error) {

	this.srcPort = uint16(mrand.Int())
	data, err := MAC_UDPPack(this.DstHost, this.srcPort, this.DstPort, []byte("xxx"))
	if err != nil {
		log.Println(err)
	}
	return data, err
}

func (this *UDPTimer) BPF() string {
	return fmt.Sprintf("icmp && host %s ", this.DstHost)
}

func (this *UDPTimer) SendPack() error {

	data, err := this.Serialize()
	if err != nil {
		log.Println(err)
		return err
	}
	log.Println("UDPTimer SendPack return")
	now := time.Now()
	this.timestampChan <- uint64(midNightDuration(&now) / time.Millisecond)
	log.Println("UDPTimer SendPack return")
	err = this.handle.WritePacketData(data)
	if err != nil {
		log.Println(err)
		return err
	}
	log.Println("UDPTimer SendPack return")
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()
	select {
	case <-ticker.C:
		//		return nil
	case <-this.syncChan:
		//		return nil
	}
	log.Println("UDPTimer SendPack return")
	return err
}

func (this *UDPTimer) CapPack(stopChan chan byte) chan uint64 {

	packetSource := gopacket.NewPacketSource(this.handle, this.handle.LinkType())
	packets := packetSource.Packets()
	rttChan := make(chan uint64)
	go func(stopChan chan byte) {
		ticker := time.NewTicker(1 * time.Second)
		defer ticker.Stop()
		var (
			err error
			ts  uint64
		)
		for {
			select {
			case packet := <-packets:

				ts, err = this.DecodeTimestamp(packet.Data())
				if err != nil {
					if err.Error() == "Not mine" {
						continue
					} else {
						log.Println(err)
						return
					}
				}
				//				log.Println(uint64(midNightDuration(&packet.Metadata().CaptureInfo.Timestamp).Nanoseconds()) / 1000000)
				rtt := uint64(midNightDuration(&packet.Metadata().CaptureInfo.Timestamp)/time.Millisecond) - ts
				//				log.Println("rtt:", rtt)
				rttChan <- rtt
				this.syncChan <- 0
			case <-ticker.C:
				<-this.timestampChan
				this.syncChan <- 0
				log.Println("timeout")
				continue
			case <-stopChan:
				log.Println("return")
				return
			}
		}
	}(stopChan)

	return rttChan

}

func (this *UDPTimer) DecodeTimestamp(data []byte) (uint64, error) {
	var (
		eth     layers.Ethernet
		ip4     layers.IPv4
		udp     layers.UDP
		icmp    layers.ICMPv4
		payload gopacket.Payload
		err     error
	)
	ts := <-this.timestampChan
	log.Println("ts", ts)
	parser := gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet, &eth, &ip4, &icmp, &payload)
	parser.IgnoreUnsupported = true
	parser.IgnorePanic = true
	decoded := []gopacket.LayerType{}

	err = parser.DecodeLayers(data, &decoded)
	if err != nil {
		log.Println(err)
		return 0, err
	}

	//解析icmp不可达数据包的payload
	udpParser := gopacket.NewDecodingLayerParser(layers.LayerTypeIPv4, &ip4, &udp)
	udpParser.IgnoreUnsupported = true
	udpParser.IgnorePanic = true
	udpDecoded := []gopacket.LayerType{}
	err = udpParser.DecodeLayers([]byte(payload), &udpDecoded)
	if err != nil {
		log.Println(err)
		return 0, err
	}
	if uint16(udp.DstPort) != this.DstPort {
		return 0, errors.New("Not mine")
	}

	return ts, nil
}

type VxLanTimer struct {
	VNI       uint32
	XHost     string
	xPort     uint16
	Payload   VxLanTimerPayload
	conn      *net.UDPConn
	lock      sync.Mutex
	rttChan   chan uint64
	recvTimes int
}

type VxLanTimerPayload interface {
	Serialize() ([]byte, error)
	DecodeTimestamp([]byte) (uint64, error)
}

func (this *VxLanTimer) Rtt(times int) (uint64, error) {

	this.lock.Lock()
	defer this.lock.Unlock()
	addr, err := net.ResolveUDPAddr("udp", fmt.Sprint(this.XHost, ":", this.xPort))
	if err != nil {
		log.Println(err)
		return 0, err
	}
	conn, err := net.DialUDP("udp", nil, addr)
	if err != nil {
		log.Println(err)
		return 0, err
	}
	this.conn = conn
	defer this.conn.Close()
	this.recvTimes = 0
	go this.receive(times)
	this.send(times)
	rtt := <-this.rttChan

	if this.recvTimes == 0 {
		//		log.Println("No reply")
		return 0, ErrNoReply
	}
	return rtt, nil

}

func (this *VxLanTimer) send(times int) error {

	for i := 0; i < times; i++ {
		data, err := this.Payload.Serialize()
		if err != nil {
			log.Println(err)
			return err
		}
		vxlan, err := VxLanPack(VNI, data)
		if err != nil {
			log.Println(err)
			return err
		}
		this.conn.Write(vxlan)
		time.Sleep(500 * time.Microsecond)
	}

	return nil
}

func (this *VxLanTimer) receive(times int) (uint64, error) {

	buffer := make([]byte, 1500)
	var (
		rtt uint64
	)
	this.conn.SetDeadline(time.Now().Add(time.Duration(times) * time.Second))
	i := 0
	for ; i < times; i++ {
		n, err := this.conn.Read(buffer)
		if err != nil {
			if strings.Contains(err.Error(), "timeout") {
				this.rttChan <- 0
				return 0, nil
			}
			log.Println(err)
			return 0, err
		}
		now := time.Now()
		nowTs := uint64(midNightDuration(&now) / time.Millisecond)
		ts, err := this.Payload.DecodeTimestamp(buffer[:n])
		if err != nil {
			log.Println(err)
			return 0, err
		}
		rtt += nowTs - ts
		time.Sleep(500 * time.Microsecond)
	}
	this.recvTimes = i + 1
	this.rttChan <- rtt

	return 0, nil
}
