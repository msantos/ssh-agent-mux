package main

import (
	"flag"
	"fmt"
	"os"
	"path"

	"go.iscode.ca/ssh-agent-mux/cmd/ssh-agent-mux/internal/proxy"
	"go.iscode.ca/ssh-agent-mux/internal/pkg/config"
)

var f = flag.NewFlagSet(os.Args[0], flag.ExitOnError)

func usage() {
	fmt.Fprintf(os.Stderr, `%s v%s
Usage: %s <command> [<option>]

Proxy ssh agent sessions.

Commands:

    proxy - proxy agent requests to one or more local or remote ssh-agents

`, path.Base(os.Args[0]), config.Version(), os.Args[0])
	fmt.Fprintf(os.Stderr, "Options:\n\n")
	f.PrintDefaults()
}

func main() {
	f.Usage = func() { usage() }
	_ = f.Parse(os.Args[1:])

	command := "help"
	var args []string

	if f.NArg() > 0 {
		command = f.Args()[0]
		args = f.Args()[1:]
	}

	os.Args = append(os.Args[:1], args...)

	switch command {
	case "proxy":
		proxy.Run()
	case "help":
		usage()
		os.Exit(2)
	case "version":
		fmt.Println(config.Version())
	default:
		fmt.Println("command not found:", command)
		os.Exit(127)
	}
}
