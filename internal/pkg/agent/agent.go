package agent

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

type Opt struct {
	extensions []Extension
}

type Proxy struct {
	*Opt

	w []agent.ExtendedAgent // to remote agents
}

type Option func(*Opt)

// WithExtensions sets the proxy behaviour for matching extensions.
func WithExtensions(e []Extension) Option {
	return func(o *Opt) {
		o.extensions = e
	}
}

// New sets configuration options for an ssh agent proxy.
func New(opt ...Option) *Opt {
	o := &Opt{}

	for _, fn := range opt {
		fn(o)
	}

	return o
}

func (o *Opt) Serve(r io.ReadWriter, ws []io.ReadWriter) error {
	agents := make([]agent.ExtendedAgent, 0, len(ws))
	for _, v := range ws {
		agents = append(agents, agent.NewClient(v))
	}

	a := &Proxy{
		Opt: o,
		w:   agents,
	}

	return agent.ServeAgent(a, r)
}

var (
	ErrNoKey         = errors.New("agent does not hold public key")
	ErrUnsupportedOp = errors.New("agent does not support operation")
)

func exists(a agent.ExtendedAgent, pubkey []byte) (bool, error) {
	keys, err := a.List()
	if err != nil {
		return false, err
	}

	for _, v := range keys {
		if bytes.Equal(v.Marshal(), pubkey) {
			return true, nil
		}
	}

	return false, nil
}

// List returns the identities known to the agent.
func (a *Proxy) List() ([]*agent.Key, error) {
	var errs error
	keys := make([]*agent.Key, 0)
	for _, v := range a.w {
		key, err := v.List()
		errs = errors.Join(errs, err)
		keys = append(keys, key...)
	}
	return keys, errs
}

// Sign has the agent sign the data using a protocol 2 key as defined
// in [PROTOCOL.agent] section 2.6.2.
func (a *Proxy) Sign(key ssh.PublicKey, data []byte) (*ssh.Signature, error) {
	for _, v := range a.w {
		ok, err := exists(v, key.Marshal())
		if err != nil {
			return nil, err
		}
		if ok {
			return v.Sign(key, data)
		}
	}
	return nil, ErrNoKey
}

// Add adds a private key to the agent.
func (a *Proxy) Add(key agent.AddedKey) error {
	return ErrUnsupportedOp
}

// Remove removes all identities with the given public key.
func (a *Proxy) Remove(key ssh.PublicKey) error {
	for _, v := range a.w {
		ok, err := exists(v, key.Marshal())
		if err != nil {
			return err
		}
		if ok {
			return v.Remove(key)
		}
	}
	return ErrNoKey
}

// RemoveAll removes all identities.
func (a *Proxy) RemoveAll() (err error) {
	for _, v := range a.w {
		err = errors.Join(err, v.RemoveAll())
	}
	return err
}

// Lock locks the agent. Sign and Remove will fail, and List will empty an empty list.
func (a *Proxy) Lock(passphrase []byte) (err error) {
	for _, v := range a.w {
		err = errors.Join(err, v.Lock(passphrase))
	}
	return err
}

// Unlock undoes the effect of Lock
func (a *Proxy) Unlock(passphrase []byte) (err error) {
	for _, v := range a.w {
		err = errors.Join(err, v.Unlock(passphrase))
	}
	return err
}

// Signers returns signers for all the known keys.
func (a *Proxy) Signers() ([]ssh.Signer, error) {
	var errs error
	signers := make([]ssh.Signer, 0)
	for _, v := range a.w {
		signer, err := v.Signers()
		signers = append(signers, signer...)
		errs = errors.Join(errs, err)
	}
	return signers, errs
}

// SignWithFlags signs like Sign, but allows for additional flags to be sent/received
func (a *Proxy) SignWithFlags(key ssh.PublicKey, data []byte, flags agent.SignatureFlags) (*ssh.Signature, error) {
	for _, v := range a.w {
		ok, err := exists(v, key.Marshal())
		if err != nil {
			return nil, err
		}
		if ok {
			return v.SignWithFlags(key, data, flags)
		}
	}
	return nil, ErrNoKey
}

// Extension processes a custom extension request. Standard-compliant agents are not
// required to support any extensions, but this method allows agents to implement
// vendor-specific methods or add experimental features. See [PROTOCOL.agent] section 4.7.
// If agent extensions are unsupported entirely this method MUST return an
// ErrExtensionUnsupported error. Similarly, if just the specific extensionType in
// the request is unsupported by the agent then ErrExtensionUnsupported MUST be
// returned.
//
// In the case of success, since [PROTOCOL.agent] section 4.7 specifies that the contents
// of the response are unspecified (including the type of the message), the complete
// response will be returned as a []byte slice, including the "type" byte of the message.
func (a *Proxy) Extension(extensionType string, contents []byte) ([]byte, error) {
	for _, v := range a.extensions {
		if !v.Match.MatchString(extensionType) {
			continue
		}
		switch v.Strategy.Behaviour {
		case All:
			return a.allExtension(extensionType, contents)
		case Any:
			return a.anyExtension(extensionType, contents)
		case First:
			return a.firstExtension(extensionType, contents)
		default:
			continue
		}
	}
	return nil, agent.ErrExtensionUnsupported
}

type Extension struct {
	Match    *regexp.Regexp
	Strategy Strategy
}

type Strategy struct {
	Behaviour Behaviour
}

type Behaviour string

const (
	None  Behaviour = ""
	All   Behaviour = "all"
	Any   Behaviour = "any"
	First Behaviour = "first"
)

var (
	ErrInvalidExtensionString = errors.New("invalid extension string")
)

func ParseExtension(s string) (Extension, error) {
	// ^pin@example.com$:any
	before, after, ok := strings.Cut(s, ":")
	if !ok {
		return Extension{}, fmt.Errorf("%w: %s", ErrInvalidExtensionString, s)
	}

	re, err := regexp.Compile(before)
	if err != nil {
		return Extension{}, nil
	}

	return Extension{
		Match: re,
		Strategy: Strategy{
			Behaviour: Behaviour(after),
		},
	}, nil
}

func (a *Proxy) allExtension(extensionType string, contents []byte) ([]byte, error) {
	response := make([]byte, 0)
	var errs error
	for _, v := range a.w {
		b, err := v.Extension(extensionType, contents)
		if errors.Is(err, agent.ErrExtensionUnsupported) {
			continue
		}
		if b != nil {
			response = append(response, b...)
		}
		errs = errors.Join(errs, err)
	}

	return response, errs
}

func (a *Proxy) anyExtension(extensionType string, contents []byte) ([]byte, error) {
	response := make([]byte, 0)
	var errs error
	found := false
	for _, v := range a.w {
		b, err := v.Extension(extensionType, contents)
		if errors.Is(err, agent.ErrExtensionUnsupported) {
			continue
		}
		if b != nil {
			response = append(response, b...)
		}
		if err == nil {
			found = true
		}
		errs = errors.Join(errs, err)
	}

	if found {
		errs = nil
	}

	return response, errs
}

func (a *Proxy) firstExtension(extensionType string, contents []byte) (b []byte, err error) {
	for _, v := range a.w {
		b, err = v.Extension(extensionType, contents)
		if errors.Is(err, agent.ErrExtensionUnsupported) {
			continue
		}
		if err == nil {
			return b, nil
		}
	}

	return b, err
}
