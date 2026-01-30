package multicast

import (
	"context"
	"net"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

type Querier struct {
	iface  *net.Interface
	srcIP  net.IP
	srcMAC net.HardwareAddr
}

func NewQuerier(iface *net.Interface) (*Querier, error) {
	srcIP, err := getInterfaceIPv4(iface)
	if err != nil {
		return nil, err
	}
	if srcIP == nil {
		return nil, nil
	}

	return &Querier{
		iface:  iface,
		srcIP:  srcIP,
		srcMAC: iface.HardwareAddr,
	}, nil
}

func (q *Querier) Run(ctx context.Context) {
	if q == nil {
		return
	}

	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()

	q.SendQuery()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			q.SendQuery()
		}
	}
}

func (q *Querier) SendQuery() {
	handle, err := pcap.OpenLive(q.iface.Name, 65536, true, pcap.BlockForever)
	if err != nil {
		return
	}
	defer handle.Close()

	eth := &layers.Ethernet{
		SrcMAC:       q.srcMAC,
		DstMAC:       net.HardwareAddr{0x01, 0x00, 0x5e, 0x00, 0x00, 0x01},
		EthernetType: layers.EthernetTypeIPv4,
	}

	ip := &layers.IPv4{
		Version:  4,
		IHL:      6,
		TTL:      1,
		Protocol: layers.IPProtocolIGMP,
		SrcIP:    q.srcIP,
		DstIP:    net.IPv4(224, 0, 0, 1),
		Options:  []layers.IPv4Option{{OptionType: 148, OptionLength: 4, OptionData: []byte{0, 0}}},
	}

	igmpPayload := buildIGMPQuery()

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{ComputeChecksums: true, FixLengths: true}

	if err := gopacket.SerializeLayers(buf, opts, eth, ip, gopacket.Payload(igmpPayload)); err != nil {
		return
	}

	handle.WritePacketData(buf.Bytes())
}

