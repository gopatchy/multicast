package multicast

import (
	"context"
	"fmt"
	"math/rand"
	"net"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"golang.org/x/net/ipv4"
)

type Conn struct {
	*ipv4.PacketConn
	rawConn   net.PacketConn
	iface     *net.Interface
	groups    []net.IP
	srcIP     net.IP
	srcMAC    net.HardwareAddr
	queryChan chan struct{}
	ctx       context.Context
	cancel    context.CancelFunc
	mu        sync.Mutex
}

func ListenMulticastUDP(network string, iface *net.Interface, gaddr *net.UDPAddr) (*Conn, error) {
	srcIP, _ := getInterfaceIPv4(iface)

	c, err := net.ListenPacket(network, gaddr.String())
	if err != nil {
		return nil, err
	}

	p := ipv4.NewPacketConn(c)
	if iface != nil {
		p.SetMulticastInterface(iface)
	}

	if err := p.JoinGroup(iface, gaddr); err != nil {
		c.Close()
		return nil, err
	}

	ctx, cancel := context.WithCancel(context.Background())

	var srcMAC net.HardwareAddr
	if iface != nil {
		srcMAC = iface.HardwareAddr
	}

	conn := &Conn{
		PacketConn: p,
		rawConn:    c,
		iface:      iface,
		groups:     []net.IP{gaddr.IP},
		srcIP:      srcIP,
		srcMAC:     srcMAC,
		queryChan:  make(chan struct{}, 1),
		ctx:        ctx,
		cancel:     cancel,
	}

	go conn.runAdvertiser()
	go conn.listenForQueries()

	return conn, nil
}

func ListenMulticastUDPPort(network string, iface *net.Interface, port int) (*Conn, error) {
	srcIP, _ := getInterfaceIPv4(iface)

	c, err := net.ListenPacket(network, fmt.Sprintf(":%d", port))
	if err != nil {
		return nil, err
	}

	p := ipv4.NewPacketConn(c)
	if iface != nil {
		p.SetMulticastInterface(iface)
	}

	ctx, cancel := context.WithCancel(context.Background())

	var srcMAC net.HardwareAddr
	if iface != nil {
		srcMAC = iface.HardwareAddr
	}

	conn := &Conn{
		PacketConn: p,
		rawConn:    c,
		iface:      iface,
		groups:     nil,
		srcIP:      srcIP,
		srcMAC:     srcMAC,
		queryChan:  make(chan struct{}, 1),
		ctx:        ctx,
		cancel:     cancel,
	}

	go conn.runAdvertiser()
	go conn.listenForQueries()

	return conn, nil
}

func (c *Conn) JoinGroup(gaddr *net.UDPAddr) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if err := c.PacketConn.JoinGroup(c.iface, gaddr); err != nil {
		return err
	}
	c.groups = append(c.groups, gaddr.IP)
	return nil
}

func (c *Conn) Close() error {
	c.cancel()
	c.mu.Lock()
	for _, groupIP := range c.groups {
		c.PacketConn.LeaveGroup(c.iface, &net.UDPAddr{IP: groupIP})
	}
	c.mu.Unlock()
	return c.rawConn.Close()
}

func (c *Conn) RawConn() net.PacketConn {
	return c.rawConn
}

func (c *Conn) runAdvertiser() {
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()

	c.sendReports()

	for {
		select {
		case <-c.ctx.Done():
			return
		case <-c.queryChan:
			delay := time.Duration(rand.Intn(1000)) * time.Millisecond
			time.Sleep(delay)
			c.sendReports()
		case <-ticker.C:
			c.sendReports()
		}
	}
}

func (c *Conn) sendReports() {
	c.mu.Lock()
	groups := append([]net.IP{}, c.groups...)
	c.mu.Unlock()

	for _, groupIP := range groups {
		c.sendReport(groupIP)
	}
}

func (c *Conn) listenForQueries() {
	handle, err := pcap.OpenLive(c.iface.Name, 65536, true, 5*time.Second)
	if err != nil {
		return
	}
	defer handle.Close()

	handle.SetBPFFilter("igmp")

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	packets := packetSource.Packets()

	for {
		select {
		case <-c.ctx.Done():
			return
		case packet, ok := <-packets:
			if !ok {
				return
			}
			if c.isQuery(packet) {
				select {
				case c.queryChan <- struct{}{}:
				default:
				}
			}
		}
	}
}

func (c *Conn) isQuery(packet gopacket.Packet) bool {
	igmpLayer := packet.Layer(layers.LayerTypeIGMP)
	if igmpLayer == nil {
		return false
	}

	switch igmp := igmpLayer.(type) {
	case *layers.IGMPv1or2:
		if igmp.Type == layers.IGMPMembershipQuery {
			if igmp.GroupAddress.IsUnspecified() {
				return true
			}
			c.mu.Lock()
			defer c.mu.Unlock()
			for _, groupIP := range c.groups {
				if igmp.GroupAddress.Equal(groupIP) {
					return true
				}
			}
		}
	case *layers.IGMP:
		if igmp.Type == layers.IGMPMembershipQuery {
			return true
		}
	}
	return false
}

func (c *Conn) sendReport(groupIP net.IP) {
	if c.srcIP == nil || c.iface == nil {
		return
	}

	handle, err := pcap.OpenLive(c.iface.Name, 65536, true, pcap.BlockForever)
	if err != nil {
		return
	}
	defer handle.Close()

	eth := &layers.Ethernet{
		SrcMAC:       c.srcMAC,
		DstMAC:       multicastIPToMAC(groupIP),
		EthernetType: layers.EthernetTypeIPv4,
	}

	ip := &layers.IPv4{
		Version:  4,
		IHL:      6,
		TTL:      1,
		Protocol: layers.IPProtocolIGMP,
		SrcIP:    c.srcIP,
		DstIP:    groupIP,
		Options:  []layers.IPv4Option{{OptionType: 148, OptionLength: 4, OptionData: []byte{0, 0}}},
	}

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{ComputeChecksums: true, FixLengths: true}
	gopacket.SerializeLayers(buf, opts, eth, ip, gopacket.Payload(buildIGMPv2Report(groupIP)))
	handle.WritePacketData(buf.Bytes())
}

func buildIGMPv2Report(groupIP net.IP) []byte {
	data := make([]byte, 8)
	data[0] = 0x16
	data[1] = 0

	ip4 := groupIP.To4()
	if ip4 != nil {
		copy(data[4:8], ip4)
	}

	checksum := igmpChecksum(data)
	data[2] = byte(checksum >> 8)
	data[3] = byte(checksum)

	return data
}

func buildIGMPQuery() []byte {
	data := make([]byte, 8)
	data[0] = 0x11
	data[1] = 100

	checksum := igmpChecksum(data)
	data[2] = byte(checksum >> 8)
	data[3] = byte(checksum)

	return data
}

func igmpChecksum(data []byte) uint16 {
	var sum uint32
	for i := 0; i < len(data)-1; i += 2 {
		sum += uint32(data[i])<<8 | uint32(data[i+1])
	}
	if len(data)%2 == 1 {
		sum += uint32(data[len(data)-1]) << 8
	}
	for sum > 0xffff {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

func multicastIPToMAC(ip net.IP) net.HardwareAddr {
	ip4 := ip.To4()
	if ip4 == nil {
		return net.HardwareAddr{0x01, 0x00, 0x5e, 0x00, 0x00, 0x01}
	}
	return net.HardwareAddr{
		0x01, 0x00, 0x5e,
		ip4[1] & 0x7f,
		ip4[2],
		ip4[3],
	}
}

func getInterfaceIPv4(iface *net.Interface) (net.IP, error) {
	addrs, err := iface.Addrs()
	if err != nil {
		return nil, err
	}

	for _, addr := range addrs {
		if ipNet, ok := addr.(*net.IPNet); ok {
			if ip4 := ipNet.IP.To4(); ip4 != nil {
				return ip4, nil
			}
		}
	}

	return nil, nil
}
