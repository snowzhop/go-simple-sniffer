package sniff

import (
	"context"
	"fmt"
	"os"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

func init() {
	for i := 0; i < 15; i++ {
		packetDelimeter = fmt.Sprintf("%s%c", packetDelimeter, 0x23AF)
	}
}

func (s *Sniffer) CapturePackets(ctx context.Context) {
	source := gopacket.NewPacketSource(s.Handle, s.Handle.LinkType())

	for packet := range source.Packets() {
		select {
		case <-ctx.Done():
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

func (s *Sniffer) WritePacketsToFile(ctx context.Context, filepath string, snaplen uint32) error {
	f, err := os.Create(filepath)
	if err != nil {
		return err
	}

	writer := pcapgo.NewWriter(f)
	writer.WriteFileHeader(snaplen, s.Handle.LinkType())

	source := gopacket.NewPacketSource(s.Handle, s.Handle.LinkType())

	for packet := range source.Packets() {
		select {
		case <-ctx.Done():
			return nil
		default:
		}
		s.processPacket(&packet)
		writer.WritePacket(packet.Metadata().CaptureInfo, packet.Data())

		s.packetCounter++
	}

	return nil
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
