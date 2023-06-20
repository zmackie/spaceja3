package main

import (
	"context"
	"flag"
	"log"
	"os"
	"sync"

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
	spawn_caps()
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

func spawn_caps() {
	// loop through interfaces
	// spawn a capture for each interface
	http_events()
}

type ja3Sig struct {
}

var eventsMutex sync.Mutex
var events []ja3Sig

func http_events() {
	//# Event loop that does pcap
	//# sends ja3/ja3s hashes to a channelcontext
	//# channel retrieves them when table is looked up
	eventsMutex.Lock()
	defer eventsMutex.Unlock()
	events = append(events, ja3Sig{})
}
