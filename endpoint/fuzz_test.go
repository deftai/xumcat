package endpoint

import (
	"net/netip"
	"path"
	"strings"
	"testing"
)

// Parse must never panic, and a parsed address's canonical form must parse
// back to the same address.
func FuzzParse(f *testing.F) {
	for _, s := range []string{"tcp:localhost:22", "tcp:[::1]:22", "unix:/run/a.sock", "exec:wc -c", "stdio", "tcp-listen:80", "tls:a:443", "tcp::", "exec:"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		a, err := Parse(s)
		if err != nil {
			return
		}
		b, err := Parse(a.String())
		if err != nil {
			t.Fatalf("canonical form %q of %q does not parse: %v", a.String(), s, err)
		}
		if a != b {
			t.Fatalf("round trip changed %q: %+v vs %+v", s, a, b)
		}
	})
}

// Whatever the pattern and target, a match must keep these promises:
// exec: is exact, unix targets are clean and absolute, IP patterns never
// match names, and host wildcards never cross a dot.
func FuzzMatch(f *testing.F) {
	for _, c := range [][2]string{
		{"tcp:10.0.0.*:22", "tcp:10.0.0.5:22"}, {"tcp:*.example.com:443", "tcp:a.example.com:443"},
		{"unix:/run/*/a.sock", "unix:/run/x/a.sock"}, {"exec:cat", "exec:cat"}, {"tcp:[::1]:*", "tcp:[::1]:8080"},
		{"tcp:*:*", "tcp:host:1"}, {"unix:@x*", "unix:@x1"}, {"tcp:[fe80::1%eth0]:*", "tcp:[fe80::1%eth0]:22"},
		{`unix:C:\run\*.sock`, `unix:C:\run\a.sock`},
	} {
		f.Add(c[0], c[1])
	}
	f.Fuzz(func(t *testing.T, pattern, target string) {
		if !Match([]string{pattern}, target) {
			return
		}
		if ValidatePattern(pattern) != nil {
			t.Fatalf("invalid pattern %q matched %q", pattern, target)
		}
		p, _ := Parse(pattern)
		a, _ := Parse(target)
		switch a.Kind {
		case "exec":
			if p.Command != a.Command {
				t.Fatalf("exec %q matched %q", pattern, target)
			}
		case "unix":
			if windowsPaths {
				if !isDrivePath(a.Path) || strings.Contains(a.Path, "/") || strings.Contains(a.Path, `\\`) || strings.Contains(a.Path, `\..`) {
					t.Fatalf("unclean Windows path %q matched %q", a.Path, pattern)
				}
			} else if !strings.HasPrefix(a.Path, "@") && (path.Clean(a.Path) != a.Path || !strings.HasPrefix(a.Path, "/")) {
				t.Fatalf("unclean unix path %q matched %q", a.Path, pattern)
			}
		case "tcp", "tls":
			if _, err := netip.ParseAddr(a.Host); err != nil && isIPPattern(p.Host) && p.Host != "*" {
				t.Fatalf("IP pattern %q matched non-IP host %q", p.Host, a.Host)
			}
			if p.Host != "*" && strings.Count(p.Host, ".") != strings.Count(strings.TrimSuffix(a.Host, "."), ".") && !strings.Contains(p.Host, ":") {
				t.Fatalf("host wildcard crossed a dot: %q matched %q", p.Host, a.Host)
			}
		}
	})
}
