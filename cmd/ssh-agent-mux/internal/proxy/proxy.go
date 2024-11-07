package proxy

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/url"
	"os"
	"path"
	"slices"
	"strings"
	"syscall"

	"github.com/msantos/ssh-agent-mux/internal/pkg/agent"
	"github.com/msantos/ssh-agent-mux/internal/pkg/config"
	"github.com/msantos/ssh-agent-mux/internal/pkg/proxy"
)

type Opt struct {
	local         *url.URL
	remotes       []*url.URL
	tlsCert       string
	tlsKey        string
	tlsRootCAs    *x509.CertPool
	tlsClientCert string
	tlsClientKey  string
	extensions    []agent.Extension
}

func usage() {
	fmt.Fprintf(os.Stderr, `%s v%s
Usage: %s proxy [<option>] <local> <remote> <...>

Options:
`, path.Base(os.Args[0]), config.Version(), os.Args[0])
	flag.PrintDefaults()
}

var errBadPEM = errors.New("bad PEM")

func cafile(rootca string) (*x509.CertPool, error) {
	if rootca == "" {
		rootca = config.Path("rootca.pem")
		if _, err := os.Stat(rootca); err != nil {
			// Use system CA root store
			return nil, nil
		}
	}

	pem, err := os.ReadFile(rootca)
	if err != nil {
		return nil, err
	}

	certs := x509.NewCertPool()

	if !certs.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("%w: %s", errBadPEM, pem)
	}

	return certs, nil
}

func handleUnixSock(l *url.URL) error {
	if l.Scheme != "unix" {
		return nil
	}

	c, err := net.Dial("unix", l.Path)

	if err == nil {
		_ = c.Close()
		return syscall.EADDRINUSE
	}

	if errors.Is(err, os.ErrNotExist) {
		return nil
	}

	return os.Remove(l.Path)
}

func urlParse(s string) (*url.URL, error) {
	u, err := url.Parse(s)
	if err != nil {
		return u, err
	}

	if u.Scheme == "" {
		u.Scheme = "unix"
	}

	return u, nil
}

func Run() {
	help := flag.Bool("help", false, "Display usage")
	tlsCert := flag.String("tls-cert", config.Path("cert.pem"), "TLS server cert")
	tlsKey := flag.String("tls-key", config.Path("key.pem"), "TLS server key")
	tlsRootCAs := flag.String("tls-rootca", "", fmt.Sprintf("TLS root CA file (default: %s, system CA root)", config.Path("rootca.pem")))
	tlsClientCert := flag.String("tls-client-cert", config.Path("client.pem"), "TLS client cert")
	tlsClientKey := flag.String("tls-client-key", config.Path("client-key.pem"), "TLS client key")
	extensions := flag.String("extensions", "", "Proxy ssh agent extensions")

	flag.Usage = func() { usage() }
	flag.Parse()

	if *help {
		usage()
		os.Exit(2)
	}

	if flag.NArg() < 2 {
		usage()
		os.Exit(2)
	}

	l, err := urlParse(flag.Arg(0))
	if err != nil {
		log.Fatalln(flag.Arg(0), err)
	}

	remotes := make([]*url.URL, 0, flag.NArg()-1)

	for i := 1; i < flag.NArg(); i++ {
		r, err := urlParse(flag.Arg(i))
		if err != nil {
			log.Fatalln(flag.Arg(i), err)
		}
		remotes = append(remotes, r)
	}

	rootcas, err := cafile(*tlsRootCAs)
	if err != nil {
		log.Fatalln(err)
	}

	x := strings.Fields(*extensions)
	ext := make([]agent.Extension, 0, len(x))

	for _, v := range x {
		e, err := agent.ParseExtension(v)
		if err != nil {
			log.Fatalln(err)
		}
		ext = append(ext, e)
	}

	o := &Opt{
		local:         l,
		remotes:       remotes,
		tlsCert:       *tlsCert,
		tlsKey:        *tlsKey,
		tlsClientCert: *tlsClientCert,
		tlsClientKey:  *tlsClientKey,
		tlsRootCAs:    rootcas,
		extensions:    ext,
	}

	if err := handleUnixSock(o.local); err != nil {
		log.Fatalln(err)
	}

	ctx := context.Background()

	if err := o.run(ctx); err != nil {
		log.Fatalln(err)
	}
}

func (o *Opt) run(ctx context.Context) error {
	l, err := o.listen()
	if err != nil {
		return err
	}

	f := func(err error) {
		log.Println(err)
	}

	clientCerts := make([]tls.Certificate, 0)

	loadKeyPair := slices.ContainsFunc(o.remotes, func(u *url.URL) bool {
		return strings.HasPrefix(u.Scheme, "mtls")
	})

	if loadKeyPair {
		certificate, err := tls.LoadX509KeyPair(o.tlsClientCert, o.tlsClientKey)
		if err != nil {
			return err
		}
		clientCerts = append(clientCerts, certificate)
	}

	p := proxy.New(
		o.remotes,
		proxy.WithLog(f),
		proxy.WithRootCAs(o.tlsRootCAs),
		proxy.WithClientCerts(clientCerts),
		proxy.WithExtensions(o.extensions),
	)

	return p.Accept(ctx, l)
}

func (o *Opt) listen() (net.Listener, error) {
	switch o.local.Scheme {
	case "tls", "mtls":
	case "unix":
		return net.Listen("unix", o.local.Path)
	default:
		return net.Listen(o.local.Scheme, o.local.Host)
	}

	certificate, err := tls.LoadX509KeyPair(o.tlsCert, o.tlsKey)
	if err != nil {
		return nil, err
	}

	config := &tls.Config{
		Certificates: []tls.Certificate{certificate},
		MinVersion:   tls.VersionTLS13,
	}

	if o.local.Scheme == "mtls" {
		config.ClientAuth = tls.RequireAndVerifyClientCert
		config.ClientCAs = o.tlsRootCAs
	}

	return tls.Listen("tcp", o.local.Host, config)
}
