# SYNOPSIm

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
