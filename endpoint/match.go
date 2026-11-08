package endpoint

import (
	"fmt"
	"net/netip"
	"path"
	"strconv"
	"strings"
)

// Allow-list patterns are endpoint addresses in which * and ? may appear.
// They are matched field by field, never as one string:
//
//   - tcp:, tls: the host and port are matched separately. * and ? never
//     match a '.', so a wildcard stays within one DNS label or one octet. A
//     host pattern made only of digits, dots and wildcards, or containing a
//     ':', is an IP pattern: it matches IP literals only, never a DNS name
//     that merely starts with the same text. A host of * alone matches any
//     host. The port must be a number from 1 to 65535.
//   - unix: * and ? stay within one path segment. The target path must be
//     absolute and already clean (no "..", ".", "//" or trailing '/'), or a
//     Linux abstract name starting with '@'. Patterns must be absolute too.
//   - exec: matched exactly. Wildcards are refused, because the command
//     runs through sh -c and a wildcard would admit shell syntax.
//   - stdio: matched exactly.
//
// There are no character classes: '[' and ']' are literal, so IPv6
// patterns such as tcp:[::1]:* work.

// ValidatePattern reports why p cannot be used as an allow-list pattern.
func ValidatePattern(p string) error {
	a, err := Parse(p)
	if err != nil {
		return err
	}
	if a.IsListen() {
		return fmt.Errorf("pattern %q: listening addresses are never allowed as targets", p)
	}
	if a.Kind == "exec" && strings.ContainsAny(a.Command, "*?") {
		return fmt.Errorf("pattern %q: exec: patterns must be exact commands; wildcards would let peers add shell syntax", p)
	}
	if a.Kind == "unix" && !strings.HasPrefix(a.Path, "/") && !strings.HasPrefix(a.Path, "@") {
		return fmt.Errorf("pattern %q: unix: patterns must be absolute paths (or @abstract names)", p)
	}
	if a.Kind == "tcp" || a.Kind == "tls" {
		if !isPortPattern(a.Port) {
			return fmt.Errorf("pattern %q: the port must be digits and wildcards", p)
		}
	}
	return nil
}

// Match reports whether addr matches one of the allow-list patterns.
// Invalid patterns match nothing.
func Match(patterns []string, addr string) bool {
	a, err := Parse(addr)
	if err != nil || a.IsListen() {
		return false
	}
	for _, p := range patterns {
		if ValidatePattern(p) != nil {
			continue
		}
		pa, _ := Parse(p)
		if pa.Kind == a.Kind && matchAddress(pa, a) {
			return true
		}
	}
	return false
}

func matchAddress(p, a Address) bool {
	switch a.Kind {
	case "tcp", "tls":
		return matchPort(p.Port, a.Port) && matchHost(p.Host, a.Host)
	case "unix":
		return unixPathOK(a.Path) && glob(p.Path, a.Path, '/')
	case "exec":
		return p.Command == a.Command
	case "stdio":
		return true
	}
	return false
}

// unixPathOK accepts absolute, clean paths ("/run/app.sock") and Linux
// abstract socket names ("@name"). Relative paths are refused: Clean keeps a
// leading "..", so a wildcard could otherwise step outside the pattern.
func unixPathOK(p string) bool {
	if strings.HasPrefix(p, "@") {
		return true
	}
	return strings.HasPrefix(p, "/") && path.Clean(p) == p
}

func isPortPattern(s string) bool {
	return s != "" && strings.Trim(s, "0123456789*?") == ""
}

func matchPort(pattern, port string) bool {
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 || strconv.Itoa(n) != port {
		return false
	}
	return glob(pattern, port, 0)
}

func isIPPattern(h string) bool {
	return strings.Contains(h, ":") || strings.Trim(h, "0123456789.*?") == ""
}

func matchHost(pattern, host string) bool {
	if pattern == "*" {
		return true
	}
	if isIPPattern(pattern) {
		ip, err := netip.ParseAddr(host)
		if err != nil {
			return false // a DNS name never matches an IP pattern
		}
		if pip, err := netip.ParseAddr(pattern); err == nil {
			return pip == ip // exact IP: compare values, not spellings
		}
		return glob(pattern, ip.String(), '.')
	}
	return glob(strings.ToLower(pattern), strings.ToLower(strings.TrimSuffix(host, ".")), '.')
}

// glob matches s against pattern, where * matches any run of characters
// and ? any one character, neither of them ever matching sep (0: none).
func glob(pattern, s string, sep byte) bool {
	var pi, si int
	star, mark := -1, 0
	for si < len(s) {
		switch {
		case pi < len(pattern) && pattern[pi] == '*':
			star, mark = pi, si
			pi++
		case pi < len(pattern) && s[si] != sep && pattern[pi] == '?':
			pi++
			si++
		case pi < len(pattern) && pattern[pi] == s[si]:
			pi++
			si++
		case star >= 0 && s[mark] != sep:
			// Let the last * absorb one more character (never a separator).
			mark++
			si = mark
			pi = star + 1
		default:
			return false
		}
	}
	for pi < len(pattern) && pattern[pi] == '*' {
		pi++
	}
	return pi == len(pattern)
}
