package main

import (
	"strings"
	"testing"
)

const me = "Jane Doe <jane@example.com>"

func commit(author, committer, message string) []byte {
	return []byte("tree 4b825dc642cb6eb9a060e54bf8d69288fbee4904\n" +
		"parent 97285316157c5af561f1b9ff2f2a63024fd20719\n" +
		"author " + author + " 1759587596 +0530\n" +
		"committer " + committer + " 1759587596 +0530\n\n" + message)
}

func TestCheckPayload(t *testing.T) {
	tests := []struct {
		name    string
		payload []byte
		ok      bool
	}{
		{"good", commit(me, me, "feat(agent): pair on demand\n"), true},
		{"breaking", commit(me, me, "feat!: drop v1\n"), true},
		{"no scope", commit(me, me, "chore: release 0.8.0\n"), true},
		{"wrong author", commit("Claude <noreply@anthropic.com>", me, "fix: x\n"), false},
		{"wrong committer", commit(me, "Claude <noreply@anthropic.com>", "fix: x\n"), false},
		{"lookalike email", commit("Jane Doe <jane@example.com.evil>", me, "fix: x\n"), false},
		{"trailer", commit(me, me, "fix: x\n\nCo-Authored-By: Claude <noreply@anthropic.com>\n"), false},
		{"body", commit(me, me, "fix: x\nmore stuff\n"), false},
		{"not conventional", commit(me, me, "Fix the thing\n"), false},
		{"unknown type", commit(me, me, "yolo: x\n"), false},
		{"empty", commit(me, me, ""), false},
		{"tag", []byte("object 9728\ntype commit\ntag v0.1.0\ntagger " + me + " 1759587596 +0530\n\nv0.1.0\n"), true},
		{"tag wrong tagger", []byte("object 9728\ntype commit\ntag v0.1.0\ntagger Someone <a@b.c> 1759587596 +0530\n\nv0.1.0\n"), false},
		{"push cert", []byte("certificate version 0.1\npusher " + me + "\n"), false},
	}
	for _, tt := range tests {
		err := checkPayload(tt.payload, me)
		if (err == nil) != tt.ok {
			t.Errorf("%s: got err %v, want ok=%v", tt.name, err, tt.ok)
		}
	}
}

func TestParseSignArgs(t *testing.T) {
	tests := []struct {
		args string
		key  string
		fd   int
		ok   bool
	}{
		{"--status-fd=2 -bsau E676", "E676", 2, true},
		{"--status-fd 2 -bsau E676", "E676", 2, true},
		{"--status-fd=2 --detach-sign --armor --local-user=E676", "E676", 2, true},
		{"--keyid-format=long --status-fd=1 --verify /tmp/sig -", "", 0, false},
		{"--list-keys", "", 0, false},
		{"-k", "", 0, false},
	}
	for _, tt := range tests {
		key, fd, ok := parseSignArgs(strings.Fields(tt.args))
		if ok != tt.ok || (ok && (key != tt.key || fd != tt.fd)) {
			t.Errorf("%q: got %q %d %v", tt.args, key, fd, ok)
		}
	}
}
