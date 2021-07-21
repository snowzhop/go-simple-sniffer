package sniff

import (
	"fmt"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func init() {
	for i := 0; i < 15; i++ {
		packetDelimeter = fmt.Sprintf("%s%c", packetDelimeter, 0x23AF)
	}
}

func (s *Sniffer) CapturePackets() {
	source := gopacket.NewPacketSource(s.Handle, s.Handle.LinkType())

	for packet := range source.Packets() {
		select {
		case <-s.AbortChan:
			return
		default:
		}
		s.processPacket(&packet)
		s.packetCounter++
	}
}

func (s *Sniffer) processPacket(packet *gopacket.Packet) {
	fmt.Printf("Packet #%d\n", s.packetCounter)
	for _, layer := range (*packet).Layers() {
		switch l := layer.(type) {
		case *layers.Ethernet:
			print(2, "Ethernet\n")
			print(4, "Src MAC: %s\n", l.SrcMAC.String())
			print(4, "Dst MAC: %s\n", l.DstMAC.String())
		case *layers.IPv4:
			print(2, "IPv4\n")
			print(4, "IPs: %s -> %s\n", l.SrcIP.String(), l.DstIP.String())
			print(4, "IP checksum: %x\n", l.Checksum)
		case *layers.TCP:
			print(2, "TCP\n")
			print(4, "Src port: %d\n", l.SrcPort)
			print(4, "Dst port: %d\n", l.DstPort)
		case *layers.UDP:

		}
	}
	fmt.Println(packetDelimeter)
}

func (s *Sniffer) PacketCount() uint64 {
	return s.packetCounter
}

func print(spaces int, format string, a ...interface{}) (int, error) {
	switch spaces {
	case 1:
		format = " " + format
	case 2:
		format = "  " + format
	case 3:
		format = "   " + format
	case 4:
		format = "    " + format
	case 5:
		format = "     " + format
	}

	return fmt.Printf(format, a...)
}
