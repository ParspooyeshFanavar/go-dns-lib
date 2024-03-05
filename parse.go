package dnslib

import (
	"crypto/sha256"
	"fmt"

	"github.com/ParspooyeshFanavar/gopacket"
	"github.com/ParspooyeshFanavar/gopacket/layers"
	"github.com/miekg/dns"
	"go.uber.org/zap"
)

func ParsePacket(packet gopacket.Packet) (*ParsePacketResult, error) {
	schema := &DnsSchema{}
	var msg *dns.Msg
	var payload []byte

	// Parse network layer information
	networkLayer := packet.NetworkLayer()
	if networkLayer == nil {
		return nil, fmt.Errorf("unknown/missing network layer for packet")
	}
	switch networkLayer.LayerType() {
	case layers.LayerTypeIPv4:
		ip4 := networkLayer.(*layers.IPv4)
		schema.SourceAddress = ip4.SrcIP.String()
		schema.DestinationAddress = ip4.DstIP.String()
		schema.Ipv = 4
	case layers.LayerTypeIPv6:
		ip6 := networkLayer.(*layers.IPv6)
		schema.SourceAddress = ip6.SrcIP.String()
		schema.DestinationAddress = ip6.DstIP.String()
		schema.Ipv = 6
	}

	// Parse DNS and transport layer information
	transportLayer := packet.TransportLayer()
	if transportLayer == nil {
		return nil, fmt.Errorf("unknown/missing transport layer for packet")
	}
	switch transportLayer.LayerType() {
	case layers.LayerTypeTCP:
		tcp := transportLayer.(*layers.TCP)
		payload = tcp.Payload
		msg = &dns.Msg{}
		if err := msg.Unpack(tcp.Payload); err != nil {
			return nil, fmt.Errorf("could not decode DNS: %v", err)
		}
		schema.SourcePort = uint16(tcp.SrcPort)
		schema.DestinationPort = uint16(tcp.DstPort)
		schema.Udp = false
		schema.Sha256 = fmt.Sprintf("%x", sha256.Sum256(tcp.Payload))
	case layers.LayerTypeUDP:
		udp := transportLayer.(*layers.UDP)
		payload = udp.Payload
		msg = &dns.Msg{}
		if err := msg.Unpack(udp.Payload); err != nil {
			return nil, fmt.Errorf("could not decode DNS: %v", err)
		}
		schema.SourcePort = uint16(udp.SrcPort)
		schema.DestinationPort = uint16(udp.DstPort)
		schema.Udp = true
		// Hash and salt packet for grouping related records
		tsSalt, err := packet.Metadata().Timestamp.MarshalBinary()
		if err != nil {
			zap.L().Sugar().Errorw("could not marshal timestamp", "error", err)
		} else {
			schema.Sha256 = fmt.Sprintf("%x", sha256.Sum256(append(tsSalt, packet.Data()...)))
		}
	}
	return &ParsePacketResult{
		Schema:  schema,
		Msg:     msg,
		Payload: payload,
	}, nil
}
