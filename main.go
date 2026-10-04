package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
)

var version = "dev"

const usage = `sigfwd: sign git commits and tags on another machine's gpg

by default sigfwd acts like gpg, so point git at it:

  git config --global gpg.program sigfwd

signing args (-bsau, --status-fd) go to the agent, everything else
(--verify etc) is handed to the local gpg untouched.

control commands start with + so they never clash with gpg args:

  sigfwd +serve    run the signing server next to your gpg
  sigfwd +agent    hold a paired session open, git talks to it
  sigfwd +pubkey   import the server's public key with ultimate trust
  sigfwd +version  print version

run sigfwd +<command> -h for its flags.
`

func main() {
	args := os.Args[1:]
	if len(args) > 0 {
		switch args[0] {
		case "+serve":
			exit(serve(args[1:]))
		case "+agent":
			exit(runAgent(args[1:]))
		case "+pubkey":
			exit(pubkey(args[1:]))
		case "+version":
			fmt.Println(version)
			return
		case "--help", "-h", "+help":
			fmt.Print(usage)
			return
		}
	}
	exit(gpgMode(args))
}

func exit(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, "sigfwd:", err)
		os.Exit(1)
	}
	os.Exit(0)
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

// per-user runtime dir: XDG_RUNTIME_DIR on linux, TMPDIR is already per-user on macos
func runtimeDir() string {
	if d := os.Getenv("XDG_RUNTIME_DIR"); d != "" {
		return d
	}
	d := filepath.Join(os.TempDir(), "sigfwd-"+strconv.Itoa(os.Getuid()))
	os.MkdirAll(d, 0o700)
	return d
}
