package sandbox

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/client"
	"github.com/docker/go-connections/nat"
	"github.com/njkleiner/ssh-honeypot/internal/config"
	"github.com/njkleiner/ssh-honeypot/internal/control"
	"github.com/njkleiner/ssh-honeypot/internal/freeport"
	"github.com/njkleiner/ssh-honeypot/internal/log"
	gossh "golang.org/x/crypto/ssh"
	"golang.org/x/exp/maps"
)

type guest struct {
	// sshPort is the port where the SSH server running inside
	// the container is exposed to the host system.
	sshPort int

	// controlPort is the port where the control HTTP server running
	// inside the container is exposed to the host system.
	controlPort int
}

type Driver struct {
	cfg config.File

	// daemon is used to communicate with the Docker daemon.
	daemon *client.Client

	// ready is a queue of started containers on standby.
	ready chan Ref

	quit chan struct{}

	// mu protects access to alive.
	mu sync.Mutex

	// alive keeps track of all running containers.
	alive map[Ref]guest
}

var _ Backend = (*Driver)(nil)

func NewDriver(cfg config.File) (*Driver, error) {
	daemon, err := client.NewClientWithOpts(client.FromEnv)

	if err != nil {
		return nil, fmt.Errorf("cannot create Docker client: %w", err)
	}

	if _, err := daemon.Info(context.Background()); err != nil {
		return nil, fmt.Errorf("cannot connect to Docker daemon: %w", err)
	}

	dv := &Driver{
		cfg: cfg,

		daemon: daemon,

		ready: make(chan Ref, cfg.Sandbox.ReadyQueueSize),

		quit: make(chan struct{}),

		alive: make(map[Ref]guest),
	}

	go dv.work()

	return dv, nil
}

func (dv *Driver) work() {
	defer close(dv.ready)

	for {
		ref, err := dv.start()

		if err != nil {
			log.Error(context.TODO(), "cannot start container", "error", err)

			select {
			case <-dv.quit:
				return // exit immediately
			case <-time.After(5 * time.Second):
				continue
			}
		}

		dv.ready <- ref

		select {
		case <-dv.quit:
			return // exit worker loop
		default:
			continue
		}
	}
}

func (dv *Driver) start() (Ref, error) {
	sshPort, err := freeport.Random()

	if err != nil {
		return "", fmt.Errorf("cannot reserve SSH port on host: %w", err)
	}

	controlPort, err := freeport.Random()

	if err != nil {
		return "", fmt.Errorf("cannot reserve control HTTP port on host: %w", err)
	}

	resp, err := dv.daemon.ContainerCreate(context.Background(),
		&container.Config{
			Image: dv.cfg.Sandbox.Image,

			ExposedPorts: nat.PortSet{
				"22/tcp":   struct{}{},
				"2023/tcp": struct{}{},
			},
		}, &container.HostConfig{
			AutoRemove: true,

			PortBindings: map[nat.Port][]nat.PortBinding{
				"22/tcp": {{
					HostIP:   "127.0.0.1",
					HostPort: fmt.Sprintf("%d", sshPort),
				}},
				"2023/tcp": {{
					HostIP:   "127.0.0.1",
					HostPort: fmt.Sprintf("%d", controlPort),
				}},
			},

			Resources: container.Resources{
				CPUPeriod: 100000,
				CPUQuota:  100000,

				Memory: int64(dv.cfg.Sandbox.Memory) << 20,
			},

			NetworkMode: container.NetworkMode(dv.cfg.Sandbox.Network),

			Runtime: dv.cfg.Sandbox.Runtime,
		}, nil, nil, "")

	if err != nil {
		return "", err
	}

	err = dv.daemon.ContainerStart(context.Background(), resp.ID,
		types.ContainerStartOptions{})

	if err != nil {
		_ = dv.daemon.ContainerRemove(context.Background(), resp.ID, types.ContainerRemoveOptions{Force: true})

		return "", err
	}

	ref := Ref(resp.ID)

	dv.mu.Lock()
	defer dv.mu.Unlock()

	dv.alive[ref] = guest{
		sshPort:     sshPort,
		controlPort: controlPort,
	}

	return ref, nil
}

func (dv *Driver) remove(ref Ref) error {
	dv.mu.Lock()
	_, ok := dv.alive[ref]
	dv.mu.Unlock()

	if !ok {
		return nil
	}

	err := dv.daemon.ContainerRemove(context.Background(), string(ref), types.ContainerRemoveOptions{Force: true})

	if err != nil {
		return err
	}

	dv.mu.Lock()
	delete(dv.alive, ref)
	dv.mu.Unlock()

	return nil
}

func (dv *Driver) Acquire(ctx context.Context) (Ref, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	select {
	case ref := <-dv.ready:
		return ref, nil
	case <-ctx.Done():
		return "", ctx.Err()
	}
}

func (dv *Driver) Connect(ctx context.Context, ref Ref, user, password string) (*gossh.Client, error) {
	dv.mu.Lock()
	port := dv.alive[ref].sshPort
	dv.mu.Unlock()

	addr := fmt.Sprintf("127.0.0.1:%d", port)

	conn, err := gossh.Dial("tcp", addr, &gossh.ClientConfig{
		User: user,
		Auth: []gossh.AuthMethod{gossh.Password(password)},

		HostKeyCallback: gossh.InsecureIgnoreHostKey(),
	})

	if err != nil {
		return nil, fmt.Errorf("cannot connect (ref=%v): %w", ref, err)
	}

	return conn, nil
}

func (dv *Driver) Usage(ctx context.Context, ref Ref) (SystemUsage, error) {
	raw, err := dv.daemon.ContainerStats(ctx, string(ref), false)

	if err != nil {
		return SystemUsage{}, err
	}

	defer raw.Body.Close()

	var stats types.StatsJSON

	if err := json.NewDecoder(raw.Body).Decode(&stats); err != nil {
		return SystemUsage{}, err
	}

	var usage SystemUsage

	preCPUUsage := float64(stats.PreCPUStats.CPUUsage.TotalUsage)
	cpuUsage := float64(stats.CPUStats.CPUUsage.TotalUsage)
	preSystemUsage := float64(stats.PreCPUStats.SystemUsage)
	systemUsage := float64(stats.CPUStats.SystemUsage)

	cpuDelta := cpuUsage - preCPUUsage
	systemDelta := systemUsage - preSystemUsage

	if systemDelta > 0.0 && cpuDelta > 0.0 {
		usage.CPU = int((cpuDelta / systemDelta) * float64(len(stats.CPUStats.CPUUsage.PercpuUsage)) * 100.0)
	}

	memUsage := float64(stats.MemoryStats.Usage)
	memLimit := float64(stats.MemoryStats.Limit)

	usage.Memory = int((memUsage / memLimit) * 100.0)

	for _, v := range stats.Networks {
		usage.BytesReceived += int(v.RxBytes)
		usage.BytesSent += int(v.TxBytes)

		usage.PacketsReceived += int(v.RxPackets)
		usage.PacketsSent += int(v.TxPackets)
	}

	return usage, nil
}

func (dv *Driver) ControlClient(ref Ref) *control.Client {
	dv.mu.Lock()
	port := dv.alive[ref].controlPort
	dv.mu.Unlock()

	return &control.Client{Host: fmt.Sprintf("127.0.0.1:%d", port)}
}

func (dv *Driver) Destroy(ref Ref) error {
	return dv.remove(ref)
}

func (dv *Driver) Close() {
	close(dv.quit) // make worker loop exit

	for range dv.ready {
		// drain standby container queue (make worker loop actually return).
		//
		// Note that this is necessary since we need to make sure that there is
		// no pending call to [Driver.start] that would modify the state of
		// [Driver.alive] after we've taken the snapshot thereof, see below.
		//
		// This loop exits when the worker loop is done because the worker loop
		// closes the ready channel when it returns.
	}

	// NOTE: we know that the worker loop as exited at this point,
	// thus we know that [Driver.alive] won't be modified again.

	dv.mu.Lock()
	alive := maps.Keys(dv.alive)
	dv.mu.Unlock()

	var wg sync.WaitGroup

	wg.Add(len(alive))

	for _, ref := range alive {
		ref := ref

		go func() {
			defer wg.Done()

			if err := dv.remove(ref); err != nil {
				log.Error(context.TODO(), "cannot remove container",
					slog.String("ref", string(ref)), slog.Any("error", err))
			}
		}()
	}

	wg.Wait()
}
