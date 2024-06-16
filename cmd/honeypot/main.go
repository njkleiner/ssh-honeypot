package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"time"

	"git.informatik.uni-hamburg.de/iss/bp-itsec-ss23/ssh-honeypot/internal/config"
	"git.informatik.uni-hamburg.de/iss/bp-itsec-ss23/ssh-honeypot/internal/elasticlog"
	"git.informatik.uni-hamburg.de/iss/bp-itsec-ss23/ssh-honeypot/internal/frontend"
	"git.informatik.uni-hamburg.de/iss/bp-itsec-ss23/ssh-honeypot/internal/sandbox"
	"github.com/docker/docker/client"
	"github.com/elastic/go-elasticsearch/v8"
	"github.com/elastic/go-elasticsearch/v8/esutil"
	"golang.org/x/sync/errgroup"
)

var console = slog.New(slog.NewJSONHandler(os.Stderr, nil))

var configFilePath = flag.String("config", "config.toml", "config file path")

func main() {
	flag.Parse()

	if err := run(); err != nil {
		console.Error("exit due to fatal error", "error", err)

		os.Exit(1)
	}
}

func run() error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	cfg, err := config.Parse(*configFilePath)

	if err != nil && !os.IsNotExist(err) {
		return err
	}

	cfg.SetDefaults()

	console.Info("loaded config file", slog.String("path", *configFilePath), slog.Any("config", cfg))

	eg, ctx := errgroup.WithContext(ctx)

	switch bw, err := createBulkWriter(cfg); {
	case err != nil:
		slog.SetDefault(console)

		console.Warn("cannot connect to ElasticSearch; printing log messages to local console only", "error", err)
	default:
		slog.SetDefault(slog.New(elasticlog.NewHandler(bw)))

		eg.Go(func() error {
			bw.Sync(ctx)

			if err := bw.Close(); err != nil {
				console.Error("cannot flush log messages", "error", err)
			}

			return nil
		})
	}

	dv, err := createDriver(cfg)

	if err != nil {
		return err
	}

	srv := frontend.NewServer(cfg, dv)

	eg.Go(func() error {
		<-ctx.Done()

		dv.Close()

		return nil
	})

	eg.Go(func() error {
		return srv.ListenAndServe(ctx)
	})

	if err := eg.Wait(); err != nil {
		return err
	}

	return nil
}

func createBulkWriter(cfg config.File) (*elasticlog.BulkWriter, error) {
	esc, err := elasticsearch.NewClient(elasticsearch.Config{
		Addresses: []string{cfg.ElasticSearch.Host},
	})

	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(cfg.ElasticSearch.ConnectTimeout)*time.Second)
	defer cancel()

	resp, err := esc.Ping(esc.Ping.WithContext(ctx))

	if err != nil {
		return nil, err
	}

	defer resp.Body.Close()

	bi, err := esutil.NewBulkIndexer(esutil.BulkIndexerConfig{
		Client: esc,
		Index:  cfg.ElasticSearch.Index,
		OnError: func(ctx context.Context, err error) {
			console.Debug("cannot flush log messages", "error", err)
		},
	})

	if err != nil {
		return nil, err
	}

	bw := elasticlog.NewBulkWriter(bi)

	return bw, nil
}

func createDriver(cfg config.File) (*sandbox.Driver, error) {
	dc, err := client.NewClientWithOpts(client.FromEnv)

	if err != nil {
		return nil, err
	}

	if _, err := dc.Info(context.Background()); err != nil {
		return nil, fmt.Errorf("cannot connect to Docker daemon: %w", err)
	}

	dv := sandbox.NewDriver(cfg, dc)

	return dv, nil
}
