# sigfwd

sign git commits and tags with your gpg key from somewhere that doesn't have your key, like a cloud box running an agent. the key stays on your machine, the remote side just asks for signatures.

```
git on remote -> sigfwd (as gpg.program) -> sigfwd +agent -> wss -> sigfwd +serve -> your gpg
```

## what it does

- `+serve` runs on your machine, listens on a unix socket, you expose it with a cloudflare tunnel
- `+agent` runs on the remote box and pairs with the server: it prints a code, the server shows the same code, you type `y` if they match
- a session lasts 5 min or 10 signatures, whichever comes first. it also dies on disconnect or when you revoke it. after that the next commit pairs again
- the server only signs commits where author and committer are you and the message is one conventional commit line (no body, no trailers). tags just need you as the tagger
- `--verify` and everything else go straight to the remote's local gpg, so run `+pubkey` once to get your key there

## your machine

```sh
go install github.com/codelif/sigfwd@latest   # or grab a binary from releases
sigfwd +serve
```

it takes the key, name and email from your global git config (`user.signingkey`, `user.name`, `user.email`). override with `-key`, `-name`, `-email`. `-ttl` and `-max` change the session limits.

the socket is `$XDG_RUNTIME_DIR/sigfwd.sock` on linux, `$TMPDIR/sigfwd-<uid>/sigfwd.sock` on macos. point cloudflared at it:

```yaml
# ~/.cloudflared/config.yml
tunnel: <tunnel id>
credentials-file: /path/to/<tunnel id>.json
ingress:
  - hostname: sign.example.com
    service: unix:/run/user/1000/sigfwd.sock
  - service: http_status:404
```

in the server terminal: `y`/`n` answers the oldest pairing request (`y 3` for a specific one), `r` revokes every session (`r 3` for one), `ls` shows what's going on.

if your pinentry is the curses one it'll fight the server for the terminal. use a gui pinentry or keep the key cached.

## remote box

```sh
curl -fsSLo /usr/local/bin/sigfwd https://github.com/codelif/sigfwd/releases/latest/download/sigfwd-linux-amd64
chmod +x /usr/local/bin/sigfwd

export SIGFWD_URL=https://sign.example.com
sigfwd +pubkey     # imports your public key, trusts it ultimately
sigfwd +agent &    # prints a pairing code, confirm it on the server

git config --global gpg.program sigfwd
git config --global user.signingkey <your key>
git config --global commit.gpgsign true
git config --global tag.gpgsign true
```

the current pairing code is also written to `$XDG_RUNTIME_DIR/sigfwd-code` (or the tmp dir above) while it waits.

## releases

push a `v*` tag and actions builds linux/macos binaries for amd64/arm64 with sha256 sums.
