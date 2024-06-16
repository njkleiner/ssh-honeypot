package config

import (
	"os"

	"github.com/pelletier/go-toml/v2"
)

type File struct {
	ElasticSearch struct {
		Host  string `toml:"host"`
		Index string `toml:"index"`

		ConnectTimeout int `toml:"connect-timeout"`
	} `toml:"elastic"`

	Frontend struct {
		ListenAddress string `toml:"listen-address"`

		MaxActiveConnections int `toml:"max-active-connections"`
		MaxConnectionTime    int `toml:"max-connection-time"`

		MaxCPU    int `toml:"max-cpu"`
		MaxMemory int `toml:"max-memory"`

		MaxBytesSent       int `toml:"max-bytes-sent"`
		MaxBytesReceived   int `toml:"max-bytes-received"`
		MaxPacketsSent     int `toml:"max-packets-sent"`
		MaxPacketsReceived int `toml:"max-packets-received"`
	} `toml:"frontend"`

	Sandbox struct {
		Image string `toml:"image"`

		Memory  int    `toml:"memory"`
		Network string `toml:"network"`

		Runtime string `toml:"runtime"`

		ReadyQueueSize int `toml:"ready-queue-size"`
	} `toml:"sandbox"`
}

func (cfg *File) SetDefaults() {
	if cfg.ElasticSearch.Host == "" {
		cfg.ElasticSearch.Host = "http://localhost:9200"
	}

	if cfg.ElasticSearch.Index == "" {
		cfg.ElasticSearch.Index = "ssh_honeypot_logs"
	}

	if cfg.ElasticSearch.ConnectTimeout == 0 {
		cfg.ElasticSearch.ConnectTimeout = 3 // 3 seconds
	}

	if cfg.Frontend.ListenAddress == "" {
		cfg.Frontend.ListenAddress = ":2022"
	}

	if cfg.Frontend.MaxActiveConnections < 0 {
		cfg.Frontend.MaxActiveConnections = 0
	}

	if cfg.Frontend.MaxConnectionTime == 0 {
		cfg.Frontend.MaxConnectionTime = 60 // 60 seconds
	}

	if cfg.Sandbox.Image == "" {
		cfg.Sandbox.Image = "guest"
	}

	if cfg.Sandbox.Memory == 0 {
		cfg.Sandbox.Memory = 50 // 50 MiB
	}

	if cfg.Sandbox.Network == "" {
		cfg.Sandbox.Network = "default"
	}

	if cfg.Sandbox.ReadyQueueSize == 0 {
		cfg.Sandbox.ReadyQueueSize = 3
	}
}

func Parse(name string) (File, error) {
	var cfg File

	f, err := os.Open(name)

	if err != nil {
		return File{}, err
	}

	defer f.Close()

	if err := toml.NewDecoder(f).Decode(&cfg); err != nil {
		return File{}, err
	}

	return cfg, nil
}
