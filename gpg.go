package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
)

func realGPG() string { return envOr("SIGFWD_GPG", "gpg") }

// git calls `gpg --status-fd=2 -bsau <key>` to sign, anything else goes to real gpg
func gpgMode(args []string) error {
	key, statusFD, ok := parseSignArgs(args)
	if !ok {
		return execGPG(args)
	}
	payload, err := io.ReadAll(os.Stdin)
	if err != nil {
		return err
	}

	c, err := net.Dial("unix", agentSocket())
	if err != nil {
		return errors.New("agent isn't running, start it with: sigfwd +agent")
	}
	defer c.Close()
	if err := json.NewEncoder(c).Encode(localReq{Key: key, Payload: payload}); err != nil {
		return err
	}
	var res msg
	if err := json.NewDecoder(c).Decode(&res); err != nil {
		return fmt.Errorf("agent hung up: %w", err)
	}
	if res.Err != "" {
		return errors.New(res.Err)
	}

	if statusFD > 0 {
		f := os.NewFile(uintptr(statusFD), "status")
		io.WriteString(f, res.Status)
	}
	_, err = os.Stdout.Write(res.Sig)
	return err
}

// returns ok only for a detached sign request, the only thing git asks for
func parseSignArgs(args []string) (key string, statusFD int, ok bool) {
	var detach, sign bool
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case strings.HasPrefix(a, "--status-fd="):
			statusFD, _ = strconv.Atoi(strings.TrimPrefix(a, "--status-fd="))
		case a == "--status-fd" && i+1 < len(args):
			i++
			statusFD, _ = strconv.Atoi(args[i])
		case a == "--detach-sign":
			detach, sign = true, true
		case a == "--sign":
			sign = true
		case a == "--armor":
		case strings.HasPrefix(a, "--local-user="):
			key = strings.TrimPrefix(a, "--local-user=")
		case a == "--local-user" && i+1 < len(args):
			i++
			key = args[i]
		case strings.HasPrefix(a, "-") && !strings.HasPrefix(a, "--") && len(a) > 1:
			// bundled short flags like -bsau, u takes the next arg
			for _, ch := range a[1:] {
				switch ch {
				case 'b':
					detach = true
				case 's':
					sign = true
				case 'a':
				case 'u':
					if i+1 < len(args) {
						i++
						key = args[i]
					}
				default:
					return "", 0, false
				}
			}
		default:
			return "", 0, false
		}
	}
	return key, statusFD, detach && sign
}

func execGPG(args []string) error {
	bin, err := exec.LookPath(realGPG())
	if err != nil {
		return err
	}
	return syscall.Exec(bin, append([]string{bin}, args...), os.Environ())
}

func pubkey(args []string) error {
	fs := flag.NewFlagSet("+pubkey", flag.ExitOnError)
	url := fs.String("url", os.Getenv("SIGFWD_URL"), "signing server (or SIGFWD_URL)")
	fs.Parse(args)
	if *url == "" {
		return errNoURL
	}

	res, err := http.Get(strings.TrimSuffix(*url, "/") + "/pubkey")
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return fmt.Errorf("server said %s", res.Status)
	}
	key, err := io.ReadAll(res.Body)
	if err != nil {
		return err
	}

	// find the primary fingerprints before importing so we only trust what we got
	cmd := exec.Command(realGPG(), "--with-colons", "--import-options", "show-only", "--import")
	cmd.Stdin = bytes.NewReader(key)
	out, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("server sent something gpg can't read: %w", err)
	}
	var fprs []string
	primary := false
	for _, l := range strings.Split(string(out), "\n") {
		f := strings.Split(l, ":")
		switch {
		case f[0] == "pub":
			primary = true
		case f[0] == "sub":
			primary = false
		case f[0] == "fpr" && primary && len(f) > 9:
			fprs = append(fprs, f[9])
			primary = false
		}
	}
	if len(fprs) == 0 {
		return errors.New("no keys in what the server sent")
	}

	cmd = exec.Command(realGPG(), "--import")
	cmd.Stdin = bytes.NewReader(key)
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return err
	}
	var trust strings.Builder
	for _, f := range fprs {
		trust.WriteString(f + ":6:\n")
	}
	cmd = exec.Command(realGPG(), "--import-ownertrust")
	cmd.Stdin = strings.NewReader(trust.String())
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return err
	}
	for _, f := range fprs {
		fmt.Println("imported and ultimately trusted", f)
	}
	return nil
}
