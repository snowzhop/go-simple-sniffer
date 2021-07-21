package main

import (
	"flag"
	"fmt"
	"os"
	"os/signal"
	"packet-sniffer/internal/sniff"

	"github.com/google/gopacket/pcap"
)

var (
	showDevices     = flag.Bool("s", false, "Show all devices. Default: false")
	bpfFilter       = flag.String("f", "", "BPF filter. Default: \"\".")
	interfaceNumber = flag.Uint("i", 0, "Interface number which can be obtained using 's' flag. Default: 0")
)

func main() {
	flag.Parse()

	devices, err := pcap.FindAllDevs()
	if err != nil {
		fmt.Fprintf(os.Stderr, "FindAllDevs() error: %v\n", err)
		os.Exit(1)
	}

	if *showDevices {
		for i, dev := range devices {
			fmt.Printf("[%d] %s", i, dev.Name)
			if len(dev.Description) > 0 {
				fmt.Printf(" - %s", dev.Description)
			}
			fmt.Println()
		}
		os.Exit(0)
	}

	chosenDevice := devices[*interfaceNumber]

	if flag.NFlag() == 0 {
		fmt.Println("Chosen default configuration.")
	}
	fmt.Printf("Chosen %s interface\n", chosenDevice.Name)

	handle, err := pcap.OpenLive(chosenDevice.Name, 1600, true, pcap.BlockForever)
	if err != nil {
		fmt.Fprintf(os.Stderr, "OpenLive() error: %v\n", err)
		os.Exit(1)
	}

	if err = handle.SetBPFFilter(*bpfFilter); err != nil {
		fmt.Fprintf(os.Stderr, "SetBPFFilter() error: %v\n", err)
		os.Exit(1)
	}

	abortSigChan := make(chan os.Signal, 1)
	signal.Notify(abortSigChan, os.Interrupt)

	sniffer := &sniff.Sniffer{Handle: handle, AbortChan: abortSigChan}

	sniffer.CapturePackets()

	fmt.Printf("\nGot %d packets.\n", sniffer.PacketCount())
}
