package main

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/dreadl0ck/ja3"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/pcapgo"
	"github.com/osquery/osquery-go"
	"github.com/osquery/osquery-go/plugin/table"
)

func main() {
	socket := flag.String("socket", "", "Path to osquery socket file")
	flag.Parse()
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
	ifaces, err := pcap.FindAllDevs()
	if err != nil {
		log.Fatalf("Failed to get network interfaces: %v", err)
	}
	for _, iface := range ifaces {
		go spawn_caps(iface.Name)
	}
	if err := server.Run(); err != nil {
		log.Fatalln(err)
	}
}

// FoobarColumns returns the columns that our table will return.
func FoobarColumns() []table.ColumnDefinition {
	return []table.ColumnDefinition{
		table.TextColumn("foo"),
		table.TextColumn("baz"),
	}
}

// FoobarGenerate will be called whenever the table is queried. It should return
// a full table scan.
func FoobarGenerate(ctx context.Context, queryContext table.QueryContext) ([]map[string]string, error) {
	return []map[string]string{
		{
			"foo": "bar",
			"baz": "baz",
		},
		{
			"foo": "bar",
			"baz": "baz",
		},
	}, nil
}

func spawn_caps(iface string) {
	// loop through interfaces
	// spawn a capture for each interface
	fmt.Println(iface)
	ja3.ReadInterface(iface, "", "")
	http_events(iface)
}

type ja3Sig struct {
	Name string
}

var eventsMutex sync.Mutex
var events []ja3Sig

func http_events(i string) {
	//# Event loop that does pcap
	//# sends ja3/ja3s hashes to a channelcontext
	//# channel retrieves them when table is looked up
	eventsMutex.Lock()
	defer eventsMutex.Unlock()
	events = append(events, ja3Sig{Name: i})
}

// taken from https://github.com/dreadl0ck/ja3/blob/master/live.go
func do_cap() (iface string, ja3s bool, asJSON bool, snaplen int, promisc bool, timeout time.Duration) {
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

	var dumpFileHandle *os.File
	var pcapWriter *pcapgo.Writer

	count := 0
	for {
		// read packet data
		data, ci, err := h.ReadPacketData()
		if err == io.EOF {
			// if Debug {
			// 	fmt.Println(count, "fingerprints.")
			// }
			return
		} else if err != nil {
			panic(err)
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
				b  strings.Builder
				nl = p.NetworkLayer()
				tl = p.TransportLayer()
			)

			// got a bare but no transport or network layer
			if tl == nil || nl == nil {
				// if Debug {
				// 	fmt.Println("got a nil layer: ", nl, tl, p.Dump(), string(bare))
				// }
				continue
			}

			r := &ja3.Record{
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

			if asJSON {

				// make it pretty please
				b, err := json.MarshalIndent(r, "", "    ")
				if err != nil {
					panic(err)
				}

				if string(b) != "null" { // no matches will result in "null" json
					// write to output io.Writer
					_, err = out.Write(b)
					if err != nil {
						panic(err)
					}

					_, err = out.Write([]byte("\n"))
					if err != nil {
						panic(err)
					}
				}
			}
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
