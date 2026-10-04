---
name: sigfwd
description: set up git in a cloud session so commits and tags are gpg signed through sigfwd, on the user's machine. use at the start of any session that will commit or tag, and whenever a commit hangs waiting for pairing.
---

# sigfwd setup

commits and tags get signed on the user's machine. nothing here holds a private key.

the server address comes from `SIGFWD_URL` in the environment. if it's not set, stop and ask the user to add it to the environment's variables. never write the address into a repo, commit, comment or chat.

## identity

fill these in for your setup. if any is still a `<placeholder>`, ask the user for it before doing anything else.

- name: `<name>`
- email: `<email>`
- key: `<primary key fingerprint>`

## 1. install

```sh
arch=$(uname -m); case $arch in x86_64) arch=amd64;; aarch64) arch=arm64;; esac
base=https://github.com/codelif/sigfwd/releases/latest/download
cd "$(mktemp -d)"
curl -fsSL -O "$base/sigfwd-linux-$arch" -O "$base/sha256sums.txt"
sha256sum --check --ignore-missing sha256sums.txt
install -m 755 "sigfwd-linux-$arch" /usr/local/bin/sigfwd
```

if the checksum fails, stop and tell the user.

## 2. git config

```sh
git config --global user.name "<name>"
git config --global user.email "<email>"
git config --global --unset-all gpg.ssh.program
git config --global gpg.format openpgp
git config --global gpg.program /usr/local/bin/sigfwd
git config --global user.signingkey <key>
git config --global commit.gpgsign true
git config --global tag.gpgsign true
```

also set `user.name` and `user.email` in every repo's local config. the platform can reset the global ones when the container restarts.

## 3. public key

```sh
sigfwd +pubkey
```

imports the key from the server and marks it ultimately trusted, so `git log --show-signature` and `git verify-commit` work locally.

## 4. agent

start `sigfwd +agent` with the Bash tool's `run_in_background`. it pairs right away and prints `pairing code XXXX-XXXX`. tell the user the code and wait until the agent logs `paired`.

sessions last 5 minutes or 10 signatures. after that a commit blocks while the agent pairs again. so run commits in the background, then read the code from `sigfwd-code` in the runtime dir (`$XDG_RUNTIME_DIR`, or `/tmp/sigfwd-<uid>` without it) or the agent's output, and send it to the user. never guess or reuse a code.

## 5. check

after the first signed commit:

```sh
git log -1 --format='%G? %GP %an <%ae>'
```

expect `G <key> <name> <<email>>`. anything else is a security problem: stop and tell the user, don't push.

## commits

- one line, conventional commit (`feat`, `fix`, `docs`, `style`, `refactor`, `perf`, `test`, `build`, `ci`, `chore`, `revert`)
- no trailers, no co-authors, the user is the only author
- the server refuses anything else, so a refused signature means the commit is wrong, fix the commit
