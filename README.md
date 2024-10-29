# SYNOPSIS

ssh-agent-mux proxy [*options*] *local* *remote* *...*

# DESCRIPTION

Proxy ssh-agent sessions to local or remote ssh-agents.

`ssh-agent-mux` proxies ssh agent requests to one or more backend ssh
agents. The agents may be running on the local system using Unix sockets
or accessed remotely over the network.

## Rationale

The default `penguin.lxd` ChromeOS container has access to hardware
tokens like the Yubikey. Other containers cannot access the token.

```mermaid
graph TD
  subgraph ChromeOS
  subgraph ubuntu ["Ubuntu"]
    ssh -->|unix socket| muxclient["ssh-agent-mux"]
    muxclient -->|unix socket| local["ssh-agent"]
  end
  subgraph ubuntults ["Ubuntu LTS"]
    ssh2["ssh"] -->|unix socket| muxclient2["ssh-agent-mux"]
    muxclient2 -->|unix socket| local2["ssh-agent"]
  end
  subgraph dev ["Dev (No Token Access)"]
    ssh3["ssh"] -->|unix socket| local3["ssh-agent"]
  end
  subgraph penguin ["penguin.lxd"]
    muxclient ==>|mTLS| muxserver["ssh-agent-mux"] -->|unix socket| tokenagent["yubikey ssh-agent"]
    muxclient2 ==>|mTLS| muxserver["ssh-agent-mux"]
    tokenagent -->|pcscd| yubikey
  end
  end
```

# BUILDING

```
go install github.com/msantos/ssh-agent-mux/cmd/ssh-agent-mux@latest
```

To build a reproducible executable from the git repository:

```
CGO_ENABLED=0 go build -trimpath -ldflags "-w" ./cmd/ssh-agent-mux
```

# EXAMPLES

## Server

```
ssh-agent-mux proxy mtls://[::]:10080 $SSH_AUTH_SOCK
```

## Client

```
ssh-agent-mux proxy agent.sock $SSH_AUTH_SOCK mtls://penguin.lxd:10080
```

# AGENT PROTOCOL EXTENSIONS

SSH agent protocol extension requests are controlled by the `--extensions`
argument. By default, extension requests return an extension unsupported
error.

The `--extensions` flag is a list of space separated matches. Each match
consists of a `behaviour`:`regexp`. The regular expression matches the
agent extension name.

```
ssh-agent-mux proxy --extensions="all:ext1@example.com first:ext2@example.com any:ext3@example.com" \
  agent.sock $SSH_AUTH_SOCK mtls://penguin.lxd:10080
```

To match all agent extensions:

```
--extensions "first:."
```

## Behaviours

Extension requests are sent to the backends in the order specified on
the command line.

Behaviours skip backends which do not support the extension. If no
backends support the extension, the proxy returns agent extension
unsupported.

all
: the extension request is sent to all backends, returning any errors

first
: the extension request is sent to each backend in order. The response
from the first backend supporting the extension is returned.

any
: the extension request is sent to each backend in order. If a backend
returns an error, the next backend is tried. If a backend returns success,
the proxy returns success.

# COMMANDS

## proxy

The listening and remote sockets are URL formatted. Supported schemes are:

* `unix`: unix socket
  * example: unix:///tmp/agent-test.s
  * paths can also be used: /tmp/agent-test.s
* `tcp`: unencrypted TCP socket
  * example: tcp:///penguin.lxd:10080
* `tls`: TLS socket
  * example: tls:///penguin.lxd:10080
* `mtls`: mutual TLS socket (TLS with client certificate)
  * example: mtls:///penguin.lxd:10080

Options are appended to the scheme:
* `insecure`: disable certificate checks for testing
  * example: mtls+insecure:///penguin.lxd:10080

### Options

extensions *string*
: Proxy ssh agent extensions

tls-cert *string*
: TLS server cert (default "/home/msantos/.config/ssh-agent-mux/cert.pem")

tls-client-cert *string*
: TLS client cert (default "/home/msantos/.config/ssh-agent-mux/client.pem")

tls-client-key *string*
: TLS client key (default "/home/msantos/.config/ssh-agent-mux/client-key.pem")

tls-key *string*
: TLS server key (default "/home/msantos/.config/ssh-agent-mux/key.pem")

tls-rootca *string*
: TLS root CA file (default: /home/msantos/.config/ssh-agent-mux/rootca.pem, system CA root)
