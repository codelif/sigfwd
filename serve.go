package main

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/coder/websocket"
)

type server struct {
	key      string
	identity string
	ttl      time.Duration
	max      int
	con      *console
	limit    *limiter
}

func serve(args []string) error {
	fs := flag.NewFlagSet("+serve", flag.ExitOnError)
	sock := fs.String("socket", filepath.Join(runtimeDir(), "sigfwd.sock"), "unix socket to listen on, point cloudflared at it")
	key := fs.String("key", gitConfig("user.signingkey"), "gpg key to sign with")
	name := fs.String("name", gitConfig("user.name"), "only sign commits/tags by this name")
	email := fs.String("email", gitConfig("user.email"), "only sign commits/tags by this email")
	ttl := fs.Duration("ttl", 5*time.Minute, "session lifetime")
	max := fs.Int("max", 10, "signatures per session")
	fs.Parse(args)

	if *key == "" || *name == "" || *email == "" {
		return errors.New("need -key, -name and -email (or set them in global git config)")
	}

	s := &server{
		key:      *key,
		identity: fmt.Sprintf("%s <%s>", *name, *email),
		ttl:      *ttl,
		max:      *max,
		con:      newConsole(),
		limit:    newLimiter(10, time.Minute),
	}

	os.Remove(*sock)
	l, err := net.Listen("unix", *sock)
	if err != nil {
		return err
	}
	os.Chmod(*sock, 0o600)

	mux := http.NewServeMux()
	mux.HandleFunc("GET /ws", s.handleWS)
	mux.HandleFunc("GET /pubkey", s.handlePubkey)

	go func() {
		sig := make(chan os.Signal, 1)
		signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
		<-sig
		l.Close()
	}()

	log.Printf("listening on %s, signing as %s with %s", *sock, s.identity, s.key)
	log.Printf("commands: y/n [id] answer a pairing, r [id] revoke a session (all if no id), ls")
	go s.con.run()
	err = http.Serve(l, s.limit.wrap(mux))
	if errors.Is(err, net.ErrClosed) {
		return nil
	}
	return err
}

func gitConfig(k string) string {
	out, _ := exec.Command("git", "config", "--global", k).Output()
	return strings.TrimSpace(string(out))
}

func clientIP(r *http.Request) string {
	// only cloudflared can reach the socket, so this header is trusted
	if ip := r.Header.Get("CF-Connecting-IP"); ip != "" {
		return ip
	}
	return "local"
}

func (s *server) handlePubkey(w http.ResponseWriter, r *http.Request) {
	out, err := exec.Command("gpg", "--armor", "--export", s.key).Output()
	if err != nil || len(out) == 0 {
		http.Error(w, "export failed", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/pgp-keys")
	w.Write(out)
}

func (s *server) handleWS(w http.ResponseWriter, r *http.Request) {
	ip := clientIP(r)
	c, err := websocket.Accept(w, r, nil)
	if err != nil {
		return
	}
	defer c.CloseNow()
	c.SetReadLimit(1 << 20)

	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()
	in := readLoop(ctx, c)
	go pinger(ctx, c)

	var hello msg
	select {
	case hello = <-in:
	case <-time.After(10 * time.Second):
		return
	}
	if hello.Type != "hello" || hello.Code == "" {
		return
	}

	id, ok, err := s.con.ask(ctx, ip, hello.Code)
	if !ok {
		reason := "denied"
		if err != nil {
			reason = err.Error()
		}
		send(ctx, c, msg{Type: "denied", Reason: reason})
		c.Close(websocket.StatusNormalClosure, "")
		return
	}

	sess := s.con.open(id, ip, s.max)
	defer s.con.close(sess)
	expires := time.Now().Add(s.ttl)
	send(ctx, c, msg{Type: "paired", Expires: expires.Unix(), Max: s.max})

	end := func(reason string) {
		log.Printf("session %d over: %s", sess.id, reason)
		send(ctx, c, msg{Type: "end", Reason: reason})
		c.Close(websocket.StatusNormalClosure, reason)
	}

	timer := time.NewTimer(s.ttl)
	defer timer.Stop()
	for {
		select {
		case <-timer.C:
			end("expired")
			return
		case <-sess.revoked:
			end("revoked")
			return
		case m, ok := <-in:
			if !ok {
				log.Printf("session %d over: disconnected", sess.id)
				return
			}
			if m.Type != "sign" {
				continue
			}
			sigb, status, err := s.sign(m)
			if err != nil {
				log.Printf("session %d: refused: %v", sess.id, err)
				send(ctx, c, msg{Type: "error", ID: m.ID, Err: err.Error()})
				continue
			}
			left := s.con.spend(sess)
			log.Printf("session %d: signed %s (%d left)", sess.id, summary(m.Payload), left)
			send(ctx, c, msg{Type: "sig", ID: m.ID, Sig: sigb, Status: status})
			if left <= 0 {
				end("signature limit reached")
				return
			}
		}
	}
}

func normKey(k string) string {
	k = strings.ToUpper(strings.TrimSpace(k))
	k = strings.TrimPrefix(k, "0X")
	return strings.TrimSuffix(k, "!")
}

func (s *server) sign(m msg) ([]byte, string, error) {
	if m.Key != "" && normKey(m.Key) != normKey(s.key) {
		return nil, "", fmt.Errorf("asked for key %s, this server only signs with %s", m.Key, s.key)
	}
	if err := checkPayload(m.Payload, s.identity); err != nil {
		return nil, "", err
	}
	var out, errb bytes.Buffer
	cmd := exec.Command("gpg", "--status-fd=2", "-bsau", s.key)
	cmd.Stdin = bytes.NewReader(m.Payload)
	cmd.Stdout = &out
	cmd.Stderr = &errb
	if err := cmd.Run(); err != nil {
		return nil, "", fmt.Errorf("gpg failed: %v: %s", err, strings.TrimSpace(errb.String()))
	}
	var status strings.Builder
	for _, l := range strings.Split(errb.String(), "\n") {
		if strings.HasPrefix(l, "[GNUPG:] ") {
			status.WriteString(l + "\n")
		}
	}
	return out.Bytes(), status.String(), nil
}

// first message line, or tag name, for the log
func summary(p []byte) string {
	head, body, _ := strings.Cut(string(p), "\n\n")
	if strings.HasPrefix(head, "object ") {
		for _, l := range strings.Split(head, "\n") {
			if t, ok := strings.CutPrefix(l, "tag "); ok {
				return "tag " + t
			}
		}
	}
	first, _, _ := strings.Cut(body, "\n")
	return fmt.Sprintf("%q", first)
}

// terminal side: pairing prompts and revokes

type pairReq struct {
	id     int
	ip     string
	code   string
	answer chan bool
}

type session struct {
	id      int
	ip      string
	left    int
	revoked chan struct{}
}

type console struct {
	mu       sync.Mutex
	nextID   int
	pending  []*pairReq
	sessions map[int]*session
}

func newConsole() *console {
	return &console{sessions: map[int]*session{}}
}

const pairTimeout = 2 * time.Minute

// session ids reuse the pair request id so the log reads straight
func (c *console) ask(ctx context.Context, ip, code string) (int, bool, error) {
	c.mu.Lock()
	c.nextID++
	req := &pairReq{id: c.nextID, ip: ip, code: code, answer: make(chan bool, 1)}
	c.pending = append(c.pending, req)
	c.mu.Unlock()
	log.Printf("pair request %d from %s, code %s. matches what the agent shows? y/n %d", req.id, ip, code, req.id)

	defer c.drop(req)
	select {
	case ok := <-req.answer:
		return req.id, ok, nil
	case <-time.After(pairTimeout):
		log.Printf("pair request %d timed out", req.id)
		return req.id, false, errors.New("nobody answered in time")
	case <-ctx.Done():
		log.Printf("pair request %d gone, client left", req.id)
		return req.id, false, ctx.Err()
	}
}

func (c *console) drop(req *pairReq) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for i, p := range c.pending {
		if p == req {
			c.pending = append(c.pending[:i], c.pending[i+1:]...)
			return
		}
	}
}

func (c *console) open(id int, ip string, max int) *session {
	c.mu.Lock()
	defer c.mu.Unlock()
	s := &session{id: id, ip: ip, left: max, revoked: make(chan struct{})}
	c.sessions[s.id] = s
	log.Printf("session %d open for %s", s.id, ip)
	return s
}

func (c *console) close(s *session) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.sessions, s.id)
}

func (c *console) spend(s *session) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	s.left--
	return s.left
}

func (c *console) run() {
	sc := bufio.NewScanner(os.Stdin)
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) == 0 {
			continue
		}
		id := 0
		if len(f) > 1 {
			fmt.Sscan(f[1], &id)
		}
		switch f[0] {
		case "y", "n":
			c.answer(id, f[0] == "y")
		case "r":
			c.revoke(id)
		case "ls":
			c.list()
		default:
			log.Printf("commands: y/n [id], r [id], ls")
		}
	}
}

// no id means the oldest pending request
func (c *console) answer(id int, ok bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, p := range c.pending {
		if id == 0 || p.id == id {
			p.answer <- ok
			return
		}
	}
	log.Printf("no such pending request")
}

func (c *console) revoke(id int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	n := 0
	for sid, s := range c.sessions {
		if id == 0 || sid == id {
			close(s.revoked)
			delete(c.sessions, sid)
			n++
		}
	}
	log.Printf("revoked %d session(s)", n)
}

func (c *console) list() {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, p := range c.pending {
		log.Printf("pending %d: %s code %s", p.id, p.ip, p.code)
	}
	for _, s := range c.sessions {
		log.Printf("session %d: %s, %d signatures left", s.id, s.ip, s.left)
	}
	if len(c.pending)+len(c.sessions) == 0 {
		log.Printf("nothing going on")
	}
}

// per-ip token bucket

type bucket struct {
	tokens float64
	last   time.Time
}

type limiter struct {
	mu     sync.Mutex
	n      float64
	per    time.Duration
	byIP   map[string]*bucket
	pruned time.Time
}

func newLimiter(n int, per time.Duration) *limiter {
	return &limiter{n: float64(n), per: per, byIP: map[string]*bucket{}}
}

func (l *limiter) allow(ip string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	if now.Sub(l.pruned) > l.per {
		for k, b := range l.byIP {
			if now.Sub(b.last) > l.per {
				delete(l.byIP, k)
			}
		}
		l.pruned = now
	}
	b, ok := l.byIP[ip]
	if !ok {
		b = &bucket{tokens: l.n, last: now}
		l.byIP[ip] = b
	}
	b.tokens = min(l.n, b.tokens+now.Sub(b.last).Seconds()*l.n/l.per.Seconds())
	b.last = now
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

func (l *limiter) wrap(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !l.allow(clientIP(r)) {
			http.Error(w, "slow down", http.StatusTooManyRequests)
			return
		}
		h.ServeHTTP(w, r)
	})
}
