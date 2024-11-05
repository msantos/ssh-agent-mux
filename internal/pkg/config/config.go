package config

import (
	"os"
	"path/filepath"
)

var version = "0.2.0"

const (
	name = "ssh-agent-mux"
)

func Version() string {
	return version
}

func Path(file string) string {
	dir, err := os.UserConfigDir()
	if err != nil {
		return file
	}

	return filepath.Join(dir, name, file)
}

func SSHAgentSock() string {
	return os.Getenv("SSH_AUTH_SOCK")
}
