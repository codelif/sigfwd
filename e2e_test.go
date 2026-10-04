package main

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// full path: agent -> websocket -> server -> real gpg with a throwaway key
func TestSignEndToEnd(t *testing.T) {
	if _, err := exec.LookPath("gpg"); err != nil {
		t.Skip("no gpg")
	}
	home, err := os.MkdirTemp("", "sigfwd-gpg")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(home)
	t.Setenv("GNUPGHOME", home)
	defer exec.Command("gpgconf", "--kill", "gpg-agent").Run()
	gen := exec.Command("gpg", "--batch", "--passphrase", "", "--quick-gen-key", "Test <test@example.com>", "ed25519", "sign", "never")
	if out, err := gen.CombinedOutput(); err != nil {
		t.Fatalf("keygen: %v %s", err, out)
	}

	s := &server{key: "test@example.com", identity: me, ttl: time.Minute, max: 2, con: newConsole(), limit: newLimiter(10, time.Minute)}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /ws", s.handleWS)
	ts := httptest.NewServer(mux)
	defer ts.Close()

	// play the human: approve whatever shows up
	stop := make(chan struct{})
	defer close(stop)
	go func() {
		for {
			select {
			case <-stop:
				return
			case <-time.After(20 * time.Millisecond):
				s.con.answer(0, true)
			}
		}
	}()

	a := &agent{url: wsURL(ts.URL)}
	payload := commit(me, me, "feat: sign over the wire\n")

	for i := 0; i < 3; i++ {
		res := a.sign(localReq{Key: "test@example.com", Payload: payload})
		if res.Err != "" {
			t.Fatalf("sign %d: %s", i, res.Err)
		}
		if !strings.Contains(res.Status, "SIG_CREATED") {
			t.Fatalf("sign %d: no SIG_CREATED in %q", i, res.Status)
		}
		verify(t, home, payload, res.Sig)
	}

	if res := a.sign(localReq{Key: "test@example.com", Payload: commit(me, me, "nope\n")}); res.Err == "" {
		t.Fatal("signed a non conventional commit")
	}
	if res := a.sign(localReq{Key: "someone-else", Payload: payload}); res.Err == "" {
		t.Fatal("signed with a key it wasn't configured for")
	}
}

func verify(t *testing.T, home string, payload, sig []byte) {
	t.Helper()
	f, _ := os.CreateTemp(home, "sig")
	f.Write(sig)
	f.Close()
	cmd := exec.Command("gpg", "--verify", f.Name(), "-")
	cmd.Stdin = bytes.NewReader(payload)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("verify: %v %s", err, out)
	}
}
