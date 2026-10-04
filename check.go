package main

import (
	"fmt"
	"regexp"
	"strings"
)

var conventional = regexp.MustCompile(`^(feat|fix|docs|style|refactor|perf|test|build|ci|chore|revert)(\([a-z0-9._/-]+\))?!?: \S.*$`)

// identity is "Name <email>"
func checkPayload(p []byte, identity string) error {
	s := string(p)
	head, body, ok := strings.Cut(s, "\n\n")
	if !ok {
		head, body = strings.TrimSuffix(s, "\n"), ""
	}
	switch {
	case strings.HasPrefix(s, "tree "):
		if err := checkPerson(head, "author", identity); err != nil {
			return err
		}
		if err := checkPerson(head, "committer", identity); err != nil {
			return err
		}
		return checkMessage(body)
	case strings.HasPrefix(s, "object "):
		return checkPerson(head, "tagger", identity)
	}
	return fmt.Errorf("not a commit or tag, refusing to sign")
}

func checkPerson(head, field, identity string) error {
	for _, l := range strings.Split(head, "\n") {
		v, ok := strings.CutPrefix(l, field+" ")
		if !ok {
			continue
		}
		// "Name <email> 1700000000 +0530"
		i := strings.LastIndex(v, ">")
		if i < 0 || v[:i+1] != identity {
			return fmt.Errorf("%s is %q, want %q", field, v, identity)
		}
		return nil
	}
	return fmt.Errorf("no %s line", field)
}

// one line, conventional, nothing after it. one line also means no trailers
func checkMessage(body string) error {
	m := strings.TrimSuffix(body, "\n")
	if strings.Contains(m, "\n") {
		return fmt.Errorf("commit message has more than one line")
	}
	if !conventional.MatchString(m) {
		return fmt.Errorf("commit message %q is not a conventional commit", m)
	}
	return nil
}
