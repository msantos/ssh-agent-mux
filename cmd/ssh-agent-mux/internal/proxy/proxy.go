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
	"strings"
	"syscall"

	"git.iscode.ca/msantos/ssh-agent-mux/internal/pkg/agent"
	"git.iscode.ca/msantos/ssh-agent-mux/internal/pkg/config"
	"git.iscode.ca/msantos/ssh-agent-mux/internal/pkg/proxy"
)

type Addr struct {
	Net  string
	Addr string
}

type Opt struct {
	local         Addr
	remotes       []proxy.Remote
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

func address(u *url.URL) string {
	if u.Scheme == "unix" {
		return u.Path
	}
	return u.Host
}

var errBadPEM = errors.New("bad PEM")

func cafile(rootca string) (*x509.CertPool, error) {
	if rootca == "" {
		return nil, nil
	}

	certs := x509.NewCertPool()
	pem, err := os.ReadFile(rootca)
	if err != nil {
		return nil, err
	}

	ok := certs.AppendCertsFromPEM(pem)
	if !ok {
		return nil, fmt.Errorf("%w: %s", errBadPEM, pem)
	}

	return certs, nil
}

func handleUnixSock(network, address string) error {
	if network != "unix" {
		return nil
	}

	c, err := net.Dial(network, address)

	if err == nil {
		c.Close()
		return syscall.EADDRINUSE
	}

	if errors.Is(err, os.ErrNotExist) {
		return nil
	}

	_ = os.Remove(address)

	return nil
}

func Run() {
	help := flag.Bool("help", false, "Display usage")
	tlsCert := flag.String("tls-cert", config.Path("cert.pem"), "TLS server cert")
	tlsKey := flag.String("tls-key", config.Path("key.pem"), "TLS server key")
	tlsRootCAs := flag.String("tls-rootca", "", "TLS root CA file")
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

	l, err := url.Parse(flag.Arg(0))
	if err != nil {
		log.Fatalln(flag.Arg(0), err)
	}

	remotes := make([]proxy.Remote, 0, flag.NArg()-1)

	for i := 1; i < flag.NArg(); i++ {
		r, err := url.Parse(flag.Arg(i))
		if err != nil {
			log.Fatalln(flag.Arg(i), err)
		}
		remotes = append(remotes, proxy.Remote{
			Net:  r.Scheme,
			Addr: address(r),
		})
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
		local: Addr{
			Net:  l.Scheme,
			Addr: address(l),
		},
		remotes:       remotes,
		tlsCert:       *tlsCert,
		tlsKey:        *tlsKey,
		tlsClientCert: *tlsClientCert,
		tlsClientKey:  *tlsClientKey,
		tlsRootCAs:    rootcas,
		extensions:    ext,
	}

	if err := handleUnixSock(o.local.Net, o.local.Addr); err != nil {
		log.Fatalln(err)
	}

	ctx := context.Background()

	if err := o.run(ctx); err != nil {
		log.Fatalln(err)
	}
}

func (o *Opt) run(ctx context.Context) error {
	l, err := o.listen(o.local.Net, o.local.Addr)
	if err != nil {
		return err
	}

	f := func(err error) {
		log.Println(err)
	}

	clientCerts := make([]tls.Certificate, 0)

	for _, v := range o.remotes {
		if strings.HasPrefix(v.Net, "mtls") {
			certificate, err := tls.LoadX509KeyPair(o.tlsClientCert, o.tlsClientKey)
			if err != nil {
				return err
			}
			clientCerts = append(clientCerts, certificate)
			break
		}
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

func (o *Opt) listen(network, address string) (net.Listener, error) {
	switch network {
	case "tls", "mtls":
	default:
		return net.Listen(network, address)
	}

	certificate, err := tls.LoadX509KeyPair(o.tlsCert, o.tlsKey)
	if err != nil {
		return nil, err
	}

	config := &tls.Config{
		Certificates: []tls.Certificate{certificate},
		MinVersion:   tls.VersionTLS13,
	}

	if network == "mtls" {
		config.ClientAuth = tls.RequireAndVerifyClientCert
		config.ClientCAs = o.tlsRootCAs
	}

	return tls.Listen("tcp", address, config)
}
