package sniff

import (
	"os"

	"github.com/google/gopacket/pcap"
)

var packetDelimeter string

type Sniffer struct {
	Handle        *pcap.Handle
	AbortChan     chan os.Signal
	packetCounter uint64
}
