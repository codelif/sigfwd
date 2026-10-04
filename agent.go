package main

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/coder/websocket"
)

func agentSocket() string {
	return envOr("SIGFWD_AGENT", filepath.Join(runtimeDir(), "sigfwd-agent.sock"))
}

// what gpg mode sends the agent over the local socket, one json object each way
type localReq struct {
	Key     string `json:"key"`
	Payload []byte `json:"payload"`
}

type agent struct {
	url  string
	mu   sync.Mutex // one signature at a time
	sess *agentSess
	ids  int
}

type agentSess struct {
	conn   *websocket.Conn
	in     <-chan msg
	cancel context.CancelFunc
}

func runAgent(args []string) error {
	fs := flag.NewFlagSet("+agent", flag.ExitOnError)
	url := fs.String("url", os.Getenv("SIGFWD_URL"), "signing server (or SIGFWD_URL)")
	sock := fs.String("socket", agentSocket(), "local socket gpg mode talks to")
	pair := fs.Bool("pair", true, "pair right away instead of on the first signature")
	fs.Parse(args)
	if *url == "" {
		return errNoURL
	}

	a := &agent{url: wsURL(*url)}

	os.Remove(*sock)
	l, err := net.Listen("unix", *sock)
	if err != nil {
		return err
	}
	os.Chmod(*sock, 0o600)
	go func() {
		sig := make(chan os.Signal, 1)
		signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
		<-sig
		l.Close()
	}()
	log.Printf("agent on %s, server %s", *sock, a.url)

	if *pair {
		go func() {
			a.mu.Lock()
			defer a.mu.Unlock()
			if err := a.ensure(); err != nil {
				log.Printf("pairing failed: %v", err)
			}
		}()
	}

	for {
		c, err := l.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}
		go a.handle(c)
	}
}

var errNoURL = errors.New("no server, pass -url or set SIGFWD_URL")

func wsURL(u string) string {
	u = strings.TrimSuffix(u, "/")
	u = strings.Replace(u, "https://", "wss://", 1)
	u = strings.Replace(u, "http://", "ws://", 1)
	return u + "/ws"
}

func (a *agent) handle(c net.Conn) {
	defer c.Close()
	var req localReq
	if err := json.NewDecoder(c).Decode(&req); err != nil {
		return
	}
	res := a.sign(req)
	json.NewEncoder(c).Encode(res)
}

func (a *agent) sign(req localReq) msg {
	a.mu.Lock()
	defer a.mu.Unlock()

	// a session can die between the check and the send, so give it one more go
	var res msg
	var err error
	for try := 0; try < 2; try++ {
		if err = a.ensure(); err != nil {
			return msg{Err: err.Error()}
		}
		res, err = a.roundtrip(req)
		if err == nil {
			return res
		}
		log.Printf("session dropped: %v", err)
		a.drop()
	}
	return msg{Err: err.Error()}
}

func (a *agent) roundtrip(req localReq) (msg, error) {
	a.ids++
	id := a.ids
	s := a.sess
	if err := send(context.Background(), s.conn, msg{Type: "sign", ID: id, Key: req.Key, Payload: req.Payload}); err != nil {
		return msg{}, err
	}
	// gpg on the other side may sit in pinentry for a while
	timeout := time.After(3 * time.Minute)
	for {
		select {
		case m, ok := <-s.in:
			if !ok {
				return msg{}, errors.New("connection closed")
			}
			switch {
			case m.Type == "end":
				return msg{}, fmt.Errorf("server ended session: %s", m.Reason)
			case m.ID != id:
				continue
			case m.Type == "error":
				// refusals are final, retrying won't help
				return msg{Err: m.Err}, nil
			case m.Type == "sig":
				return m, nil
			}
		case <-timeout:
			return msg{}, errors.New("server took too long")
		}
	}
}

// make sure there is a live paired session, pairing a new one if needed
func (a *agent) ensure() error {
	if a.sess != nil {
		select {
		case m, ok := <-a.sess.in:
			// anything unprompted here is the session ending
			if ok {
				log.Printf("server ended session: %s", m.Reason)
			}
			a.drop()
		default:
			return nil
		}
	}

	ctx, cancel := context.WithCancel(context.Background())
	dctx, dcancel := context.WithTimeout(ctx, 30*time.Second)
	c, _, err := websocket.Dial(dctx, a.url, nil)
	dcancel()
	if err != nil {
		cancel()
		return fmt.Errorf("can't reach %s: %w", a.url, err)
	}
	c.SetReadLimit(1 << 20)
	in := readLoop(ctx, c)
	go pinger(ctx, c)

	code := pairCode()
	if err := send(ctx, c, msg{Type: "hello", Code: code}); err != nil {
		cancel()
		c.CloseNow()
		return err
	}
	log.Printf("pairing code %s, confirm it on the server", code)
	writeCode(code)

	select {
	case m, ok := <-in:
		switch {
		case !ok:
			err = errors.New("server hung up while pairing")
		case m.Type == "paired":
			log.Printf("paired, %d signatures until %s", m.Max, time.Unix(m.Expires, 0).Format(time.TimeOnly))
			a.sess = &agentSess{conn: c, in: in, cancel: cancel}
			writeCode("")
			return nil
		default:
			err = fmt.Errorf("pairing denied: %s", m.Reason)
		}
	case <-time.After(pairTimeout + 10*time.Second):
		err = errors.New("pairing timed out")
	}
	writeCode("")
	cancel()
	c.CloseNow()
	return err
}

func (a *agent) drop() {
	if a.sess == nil {
		return
	}
	a.sess.cancel()
	a.sess.conn.CloseNow()
	a.sess = nil
}

// no 0/O/1/I so it reads fine over chat
const codeChars = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"

func pairCode() string {
	b := make([]byte, 8)
	rand.Read(b)
	for i := range b {
		b[i] = codeChars[int(b[i])%len(codeChars)]
	}
	return string(b[:4]) + "-" + string(b[4:])
}

// the current code also goes to a file, handy when the agent runs in the background
func codeFile() string { return filepath.Join(runtimeDir(), "sigfwd-code") }

func writeCode(code string) {
	if code == "" {
		os.Remove(codeFile())
		return
	}
	os.WriteFile(codeFile(), []byte(code+"\n"), 0o600)
}
