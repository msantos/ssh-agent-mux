package proxy

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/url"
	"strings"

	"github.com/msantos/ssh-agent-mux/internal/pkg/agent"
)

type Opt struct {
	remotes        []*url.URL
	log            func(error)
	rootCAs        *x509.CertPool
	tlsClientCerts []tls.Certificate
	extensions     []agent.Extension
}

type Option func(*Opt)

// WithRootCAs sets CA roots for TLS connections.
func WithRootCAs(rootCAs *x509.CertPool) Option {
	return func(o *Opt) {
		o.rootCAs = rootCAs
	}
}

// WithClientCerts sets the mTLS client certificates.
func WithClientCerts(certs []tls.Certificate) Option {
	return func(o *Opt) {
		o.tlsClientCerts = certs
	}
}

// WithLog sets the logging function.
func WithLog(f func(error)) Option {
	return func(o *Opt) {
		if f != nil {
			o.log = f
		}
	}
}

// WithExtensions sets the proxy behaviour for matching extensions.
func WithExtensions(e []agent.Extension) Option {
	return func(o *Opt) {
		o.extensions = e
	}
}

// New sets configuration options for a proxy.
func New(remotes []*url.URL, opt ...Option) *Opt {
	o := &Opt{
		remotes: remotes,
		log:     func(_ error) {},
	}

	for _, fn := range opt {
		fn(o)
	}

	return o
}

func (o *Opt) Accept(ctx context.Context, l net.Listener) error {
	for {
		select {
		case <-ctx.Done():
			return nil
		default:
		}

		c, err := l.Accept()
		if err != nil {
			return err
		}

		go o.proxy(ctx, c)
	}
}

func (o *Opt) dial(remote *url.URL) (net.Conn, error) {
	network, opt, _ := strings.Cut(remote.Scheme, "+")

	switch network {
	case "tcp":
		return net.Dial(network, remote.Host)
	case "unix":
		return net.Dial(network, remote.Path)
	case "tls", "mtls":
	default:
		return nil, net.UnknownNetworkError(network)
	}

	c, err := net.Dial("tcp", remote.Host)
	if err != nil {
		return nil, err
	}

	serverName, _, err := net.SplitHostPort(remote.Host)
	if err != nil {
		return nil, err
	}

	config := &tls.Config{
		ServerName: serverName,
		RootCAs:    o.rootCAs,
		MinVersion: tls.VersionTLS13,
	}

	if network == "mtls" {
		config.Certificates = o.tlsClientCerts
	}

	if opt == "insecure" {
		config.InsecureSkipVerify = true
	}

	return tls.Client(c, config), nil
}

func (o *Opt) proxy(ctx context.Context, client net.Conn) {
	defer client.Close()

	remotes := make([]io.ReadWriter, 0, len(o.remotes))
	for _, v := range o.remotes {
		c, err := o.dial(v)
		if err != nil {
			o.log(err)
			return
		}
		defer c.Close()
		remotes = append(remotes, c)
	}

	if err := agent.New(agent.WithExtensions(o.extensions)).Serve(client, remotes); err != nil && !errors.Is(err, io.EOF) {
		o.log(err)
	}
}
