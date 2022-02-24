package pcap

import (
	"encoding/binary"
	"errors"
	"time"
)

type PacketTime struct {
	Sec  int32
	Usec int32
}

// Packet is a single packet parsed from a pcap file.
type Packet struct {
	// porting from 'pcap_pkthdr' struct
	Time   time.Time // packet send/receive time
	Caplen uint32    // bytes stored in the file (caplen <= len)
	Len    uint32    // bytes sent/received

	Data   []byte // packet data

	Type    int // protocol type, see LINKTYPE_*
	DestMac uint64
	SrcMac  uint64

	// We only care about IP and UDP headers for pcap
	Iphdr   Iphdr
	Udphdr  Udphdr
	Payload []byte        // remaining non-header bytes
}

// Decode decodes the headers of a Packet.
func (p *Packet) Decode() error {
	if len(p.Data) <= 14 {
		return errors.New("invalid header")
	}
	p.Type = int(binary.BigEndian.Uint16(p.Data[12:14]))
	p.DestMac = decodemac(p.Data[0:6])
	p.SrcMac = decodemac(p.Data[6:12])
	p.Payload = p.Data[14:]

	switch p.Type {
	case TYPE_IP:
		p.decodeIp()
	}

	return nil
}

func (p *Packet) decodeIp() {
	if len(p.Payload) < 20 {
		return
	}
	pkt := p.Payload

	p.Iphdr.Version = uint8(pkt[0]) >> 4
	p.Iphdr.Ihl = uint8(pkt[0]) & 0x0F
	p.Iphdr.Tos = pkt[1]
	p.Iphdr.Length = binary.BigEndian.Uint16(pkt[2:4])
	p.Iphdr.Id = binary.BigEndian.Uint16(pkt[4:6])
	flagsfrags := binary.BigEndian.Uint16(pkt[6:8])
	p.Iphdr.Flags = uint8(flagsfrags >> 13)
	p.Iphdr.FragOffset = flagsfrags & 0x1FFF
	p.Iphdr.Ttl = pkt[8]
	p.Iphdr.Protocol = pkt[9]
	p.Iphdr.Checksum = binary.BigEndian.Uint16(pkt[10:12])
	p.Iphdr.SrcIp = pkt[12:16]
	p.Iphdr.DestIp = pkt[16:20]
	pEnd := int(p.Iphdr.Length)
	if pEnd > len(pkt) {
		pEnd = len(pkt)
	}
	pIhl := int(p.Iphdr.Ihl) * 4
	if pIhl > pEnd {
		pIhl = pEnd
	}
	p.Payload = pkt[pIhl:pEnd]

	switch p.Iphdr.Protocol {
	case IP_UDP:
		p.decodeUdp()
	case IP_INIP:
		p.decodeIp()
	}
}

func (p *Packet) decodeUdp() {
	if len(p.Payload) < 8 {
		return
	}
	pkt := p.Payload
	p.Udphdr.SrcPort = binary.BigEndian.Uint16(pkt[0:2])
	p.Udphdr.DestPort = binary.BigEndian.Uint16(pkt[2:4])
	p.Udphdr.Length = binary.BigEndian.Uint16(pkt[4:6])
	p.Udphdr.Checksum = binary.BigEndian.Uint16(pkt[6:8])
	p.Payload = pkt[8:]
}

