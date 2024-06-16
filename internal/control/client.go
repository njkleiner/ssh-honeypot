package control

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/gorilla/websocket"
)

type Client struct {
	Host string
}

func (c *Client) Ping(ctx context.Context) error {
	delay := 1 * time.Second

	tick := time.NewTicker(delay)
	defer tick.Stop()

	for {
		code, err := c.ping(ctx)

		switch {
		case err != nil:
			tick.Reset(delay) // network error; try again
		case code == http.StatusOK:
			return nil // ready
		case code == http.StatusServiceUnavailable:
			tick.Reset(delay) // not ready yet; try again
		default:
			return fmt.Errorf("%d %s", code, http.StatusText(code))
		}

		select {
		case <-tick.C:
			continue
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

func (c *Client) ping(ctx context.Context) (int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		fmt.Sprintf("http://%s/ping", c.Host), nil)

	if err != nil {
		return 0, fmt.Errorf("cannot create request: %w", err)
	}

	resp, err := http.DefaultClient.Do(req)

	if err != nil {
		return 0, err
	}

	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()

	return resp.StatusCode, nil
}

func (c *Client) Claim(ctx context.Context, info AuthInfo) error {
	body, err := json.Marshal(info)

	if err != nil {
		return fmt.Errorf("cannot marshal body: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		fmt.Sprintf("http://%s/claim", c.Host), bytes.NewReader(body))

	if err != nil {
		return fmt.Errorf("cannot create request: %w", err)
	}

	resp, err := http.DefaultClient.Do(req)

	if err != nil {
		return err
	}

	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()

	if code := resp.StatusCode; code != http.StatusAccepted {
		return fmt.Errorf("%d %s", code, http.StatusText(code))
	}

	return nil
}

func (c *Client) Subscribe(ctx context.Context, ch chan<- Event) error {
	defer close(ch)

	conn, _, err := websocket.DefaultDialer.DialContext(ctx,
		fmt.Sprintf("ws://%s/subscribe", c.Host), nil)

	if err != nil {
		return fmt.Errorf("cannot connect: %w", err)
	}

	defer conn.Close()

	for {
		var evt Event

		switch err := conn.ReadJSON(&evt); {
		case websocket.IsCloseError(err, websocket.CloseAbnormalClosure):
			return nil
		case err != nil:
			return err
		default:
			ch <- evt
		}
	}
}
