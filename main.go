package main

import (
	"context"
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/dreadl0ck/ja3"
	"github.com/fatih/structs"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/pcapgo"
	"github.com/osquery/osquery-go"
	"github.com/osquery/osquery-go/plugin/table"
)

var debug bool

var eventsMutex sync.Mutex
var events []Record

func main() {
	socket := flag.String("socket", "", "Path to osquery socket file")
	debug_flag := flag.Bool("debug", false, "debug mode")
	flag.Parse()
	debug = *debug_flag
	if *socket == "" {
		log.Fatalf(`Usage: %s --socket SOCKET_PATH`, os.Args[0])
	}

	server, err := osquery.NewExtensionManagerServer("foobar", *socket)
	if err != nil {
		log.Fatalf("Error creating extension: %s\n", err)
	}

	// Create and register a new table plugin with the server.
	// table.NewPlugin requires the table plugin name,
	// a slice of Columns and a Generate function.
	server.RegisterPlugin(table.NewPlugin("foobar", FoobarColumns(), FoobarGenerate))
	go http_events()
	if err := server.Run(); err != nil {
		log.Fatalln(err)
	}
}

// // Record contains all information for a calculated JA3
type Record struct {
	DestinationIP   string  `json,structs:"destination_ip"`
	DestinationPort int     `json,structs:"destination_port"`
	JA3             string  `json,structs:"ja3"`
	JA3Digest       string  `json,structs:"ja3_digest"`
	JA3S            string  `json,structs:"ja3s"`
	JA3SDigest      string  `json,structs:"ja3s_digest"`
	SourceIP        string  `json,structs:"source_ip"`
	SourcePort      int     `json,structs:"source_port"`
	Timestamp       float64 `json,structs:"timestamp"`
}

func (r Record) Map() map[string]string {
	t := map[string]string{}

	m := structs.Map(r)

	for k, v := range m {
		t[k] = fmt.Sprintf("%v", v)
	}
	return t
}

// FoobarColumns returns the columns that our table will return.
func FoobarColumns() []table.ColumnDefinition {
	return []table.ColumnDefinition{
		table.TextColumn("destination_ip"),
		table.IntegerColumn("destination_port"),
		table.TextColumn("ja3"),
		table.TextColumn("ja3_digest"),
		table.TextColumn("ja3s"),
		table.TextColumn("ja3s_digest"),
		table.TextColumn("source_ip"),
		table.IntegerColumn("source_port"),
		table.DoubleColumn("timestamp"),
	}
}

// FoobarGenerate will be called whenever the table is queried. It should return
// a full table scan.
func FoobarGenerate(ctx context.Context, queryContext table.QueryContext) ([]map[string]string, error) {
	eventsJson := []map[string]string{}
	eventsMutex.Lock()
	defer eventsMutex.Unlock()
	for _, r := range events {
		eventsJson = append(eventsJson, r.Map())
	}
	return eventsJson, nil
}

func http_events() {
	//# Event loop that does pcap
	//# sends ja3/ja3s hashes to a channelcontext
	//# channel retrieves them when table is looked up
	// ifaces, err := pcap.FindAllDevs()
	// if err != nil {
	// 	log.Fatalf("Failed to get network interfaces: %v", err)
	// }
	ja3Chan := make(chan Record)
	// for _, iface := range ifaces {
	// 	fmt.Println(iface)
	// u, _ := time.ParseDuration("1s")
	go do_cap(ja3Chan, "eth0", true, 0, true, pcap.BlockForever)
	// }

	for {
		ja3Record, ok := <-ja3Chan
		if !ok {
			return
		}
		eventsMutex.Lock()
		events = append(events, ja3Record)
		defer eventsMutex.Unlock()

	}

}

// taken from https://github.com/dreadl0ck/ja3/blob/master/live.go
func do_cap(cbChan chan Record, iface string, ja3s bool, snaplen int, promisc bool, timeout time.Duration) {
	h, err := pcap.OpenLive(iface, int32(snaplen), promisc, timeout)
	if err != nil {
		panic(err)
	}
	defer h.Close()

	// if strings.TrimSpace(bpfFilter) != "" {
	// 	if err := h.SetBPFFilter(bpfFilter); err != nil {
	// 		panic(err)
	// 	}
	// }

	var pcapWriter *pcapgo.Writer

	count := 0
	for {
		// read packet data
		data, ci, err := h.ReadPacketData()
		if debug {
			fmt.Println("packet data", data[0:10])
		}
		if err == io.EOF {
			if debug {
				fmt.Println(count, "fingerprints.")
			}
			return
		} else if err != nil {
			fmt.Println("error reading packets:", err)
			return
		}

		var (
			// create gopacket
			p        = gopacket.NewPacket(data, layers.LinkTypeEthernet, gopacket.Lazy)
			bare     = ja3.BarePacket(p)
			isServer bool
		)

		if ja3s && len(bare) == 0 {
			bare = ja3.BarePacketJa3s(p)
			isServer = true
		}

		// check if we got a result
		if len(bare) > 0 {
			count++

			if pcapWriter != nil {
				pcapWriter.WritePacket(ci, data)
			}

			var (
				// b  strings.Builder
				nl = p.NetworkLayer()
				tl = p.TransportLayer()
			)

			// got a bare but no transport or network layer
			if tl == nil || nl == nil {
				if debug {
					fmt.Println("got a nil layer: ", nl, tl, p.Dump(), string(bare))
				}
				continue
			}

			r := Record{
				DestinationIP:   nl.NetworkFlow().Dst().String(),
				DestinationPort: int(binary.BigEndian.Uint16(tl.TransportFlow().Dst().Raw())),
				SourceIP:        nl.NetworkFlow().Src().String(),
				SourcePort:      int(binary.BigEndian.Uint16(tl.TransportFlow().Src().Raw())),
				Timestamp:       timeToFloat(ci.Timestamp),
			}

			digest := ja3.BareToDigestHex(bare)
			if isServer {
				r.JA3S = string(bare)
				r.JA3SDigest = digest
			} else {
				r.JA3 = string(bare)
				r.JA3Digest = digest
			}
			cbChan <- r
		}
	}
}

// convert a time.Time to a string timestamp in the format seconds.microseconds
func timeToString(t time.Time) string {
	micro := fmt.Sprintf("%06d", t.Nanosecond()/1000)
	return strconv.FormatInt(t.Unix(), 10) + "." + micro
}

func timeStringToFloat64(t string) float64 {
	f, err := strconv.ParseFloat(t, 64)
	if err != nil {
		fmt.Println("[ERROR] failed to convert", t, "to float64. error:", err)
	}
	return f
}

func timeToFloat(t time.Time) float64 {
	return timeStringToFloat64(timeToString(t))
}
