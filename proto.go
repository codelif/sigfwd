package main

import (
	"context"
	"encoding/json"
	"time"

	"github.com/coder/websocket"
)

// one message shape for everything, unused fields stay empty
//
// agent -> server: hello{code}, sign{id, key, payload}
// server -> agent: paired{expires, max}, denied{reason}, sig{id, sig, status}, error{id, err}, end{reason}
type msg struct {
	Type    string `json:"type"`
	ID      int    `json:"id,omitempty"`
	Code    string `json:"code,omitempty"`
	Key     string `json:"key,omitempty"`
	Payload []byte `json:"payload,omitempty"`
	Sig     []byte `json:"sig,omitempty"`
	Status  string `json:"status,omitempty"`
	Err     string `json:"err,omitempty"`
	Reason  string `json:"reason,omitempty"`
	Expires int64  `json:"expires,omitempty"`
	Max     int    `json:"max,omitempty"`
}

// cloudflare kills websockets that stay quiet for ~100s
const pingEvery = 20 * time.Second

func send(ctx context.Context, c *websocket.Conn, m msg) error {
	b, err := json.Marshal(m)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	return c.Write(ctx, websocket.MessageText, b)
}

// reads until the conn dies, closes the returned channel when it does
func readLoop(ctx context.Context, c *websocket.Conn) <-chan msg {
	ch := make(chan msg, 4)
	go func() {
		defer close(ch)
		for {
			_, b, err := c.Read(ctx)
			if err != nil {
				return
			}
			var m msg
			if json.Unmarshal(b, &m) != nil {
				return
			}
			ch <- m
		}
	}()
	return ch
}

func pinger(ctx context.Context, c *websocket.Conn) {
	t := time.NewTicker(pingEvery)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			pctx, cancel := context.WithTimeout(ctx, pingEvery)
			err := c.Ping(pctx)
			cancel()
			if err != nil {
				c.CloseNow()
				return
			}
		}
	}
}
