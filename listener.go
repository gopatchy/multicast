package multicast

import (
	"context"
	"net"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

type JoinLeaveHandler func(sourceIP, groupIP net.IP, join bool)

type Listener struct {
	iface       *net.Interface
	handle      *pcap.Handle
	joinHandler JoinLeaveHandler
}

func NewListener(iface *net.Interface, joinHandler JoinLeaveHandler) (*Listener, error) {
	handle, err := pcap.OpenLive(iface.Name, 65536, true, 5*time.Second)
	if err != nil {
		return nil, err
	}

	if err := handle.SetBPFFilter("igmp"); err != nil {
		handle.Close()
		return nil, err
	}

	return &Listener{
		iface:       iface,
		handle:      handle,
		joinHandler: joinHandler,
	}, nil
}

func (l *Listener) Run(ctx context.Context) {
	defer l.handle.Close()

	packetSource := gopacket.NewPacketSource(l.handle, l.handle.LinkType())
	packets := packetSource.Packets()

	for {
		select {
		case <-ctx.Done():
			return
		case packet, ok := <-packets:
			if !ok {
				return
			}
			l.handlePacket(packet)
		}
	}
}

func (l *Listener) Close() {
	l.handle.Close()
}

func (l *Listener) handlePacket(packet gopacket.Packet) {
	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	if ipLayer == nil {
		return
	}
	ip := ipLayer.(*layers.IPv4)
	sourceIP := ip.SrcIP

	igmpLayer := packet.Layer(layers.LayerTypeIGMP)
	if igmpLayer == nil {
		return
	}

	switch igmp := igmpLayer.(type) {
	case *layers.IGMPv1or2:
		l.handleIGMPv1or2(sourceIP, igmp)
	case *layers.IGMP:
		l.handleIGMPv3(sourceIP, igmp)
	}
}

func (l *Listener) handleIGMPv1or2(sourceIP net.IP, igmp *layers.IGMPv1or2) {
	switch igmp.Type {
	case layers.IGMPMembershipReportV1, layers.IGMPMembershipReportV2:
		groupIP := igmp.GroupAddress
		if !groupIP.IsMulticast() || groupIP.IsLinkLocalMulticast() {
			return
		}
		if l.joinHandler != nil {
			l.joinHandler(sourceIP, groupIP, true)
		}

	case layers.IGMPLeaveGroup:
		groupIP := igmp.GroupAddress
		if l.joinHandler != nil {
			l.joinHandler(sourceIP, groupIP, false)
		}
	}
}

func (l *Listener) handleIGMPv3(sourceIP net.IP, igmp *layers.IGMP) {
	if igmp.Type != layers.IGMPMembershipReportV3 {
		return
	}

	for _, record := range igmp.GroupRecords {
		groupIP := record.MulticastAddress
		if !groupIP.IsMulticast() || groupIP.IsLinkLocalMulticast() {
			continue
		}

		switch record.Type {
		case layers.IGMPIsEx, layers.IGMPToEx, layers.IGMPIsIn, layers.IGMPToIn:
			if l.joinHandler != nil {
				l.joinHandler(sourceIP, groupIP, true)
			}
		case layers.IGMPBlock:
			if l.joinHandler != nil {
				l.joinHandler(sourceIP, groupIP, false)
			}
		}
	}
}
