package sandbox

type Ref string

type SystemUsage struct {
	CPU    int `json:"cpu"`
	Memory int `json:"memory"`

	BytesSent     int `json:"bytes_sent"`
	BytesReceived int `json:"bytes_received"`

	PacketsSent     int `json:"packets_sent"`
	PacketsReceived int `json:"packets_received"`
}
