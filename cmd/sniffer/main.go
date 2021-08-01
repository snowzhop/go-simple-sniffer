package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"os/user"
	"packet-sniffer/internal/sniff"

	"github.com/google/gopacket/pcap"
)

var (
	showDevices     = flag.Bool("s", false, "Show all devices. Default: false")
	bpfFilter       = flag.String("f", "", "BPF filter. Default: \"\".")
	interfaceNumber = flag.Uint("i", 0, "Interface number which can be obtained using 's' flag. Default: 0")
	snaplen         = flag.Uint("sl", 1600, "Snapshot length. Default: 1600")
	filepath        = flag.String("w", "", "Write packets to pcap file. Default \"\".")
)

func main() {
	flag.Parse()

	user, err := user.Current()
	if err != nil {
		fmt.Fprintf(os.Stderr, "user.Current() error: %v\n", err)
		os.Exit(1)
	}

	if user.Uid != "0" {
		fmt.Fprintf(os.Stderr, "Error: You don't have permission to capture on that device (you need root).\n")
		os.Exit(1)
	}

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

	handle, err := pcap.OpenLive(chosenDevice.Name, int32(*snaplen), true, pcap.BlockForever)
	if err != nil {
		fmt.Fprintf(os.Stderr, "OpenLive() error: %v\n", err)
		os.Exit(1)
	}

	if err = handle.SetBPFFilter(*bpfFilter); err != nil {
		fmt.Fprintf(os.Stderr, "SetBPFFilter() error: %v\n", err)
		os.Exit(1)
	}

	sniffer := &sniff.Sniffer{Handle: handle}

	ctx, _ := signal.NotifyContext(context.Background(), os.Interrupt)

	if len(*filepath) == 0 {
		sniffer.CapturePackets(ctx)
	} else {
		sniffer.WritePacketsToFile(ctx, *filepath, uint32(*snaplen))
	}

	fmt.Printf("\nGot %d packets.\n", sniffer.PacketCount())
}
