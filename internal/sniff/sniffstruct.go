package sniff

import (
	"github.com/google/gopacket/pcap"
)

var packetDelimeter string

type Sniffer struct {
	Handle        *pcap.Handle
	packetCounter uint64
}
