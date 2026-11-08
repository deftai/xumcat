package endpoint

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestMatchFieldByField(t *testing.T) {
	pathStyle(t, false)
	for _, tc := range []struct {
		pattern, target string
		want            bool
	}{
		// Still works.
		{"tcp:localhost:*", "tcp:localhost:22", true},
		{"tcp:localhost:*", "tcp:LOCALHOST:22", true},
		{"tcp:localhost:80*", "tcp:localhost:8080", true},
		{"tcp:*:443", "tcp:example.com:443", true},
		{"tcp:*:443", "tcp:10.1.2.3:443", true},
		{"tcp:*.example.com:443", "tcp:api.example.com:443", true},
		{"tcp:10.0.0.?:22", "tcp:10.0.0.5:22", true},
		{"tcp:10.0.0.*:22", "tcp:10.0.0.200:22", true},
		{"unix:/run/app/*.sock", "unix:/run/app/a.sock", true},
		{"exec:cat", "exec:cat", true},
		{"stdio", "stdio", true},

		// A wildcard stays within one DNS label.
		{"tcp:*.example.com:443", "tcp:a.b.example.com:443", false},
		{"tcp:*.example.com:443", "tcp:example.com.evil.test:443", false},

		// An IP pattern matches IP literals only, never a DNS name with the same prefix.
		{"tcp:10.0.0.*:22", "tcp:10.0.0.1.example.net:22", false},
		{"tcp:10.0.0.*:22", "tcp:10.0.0.1.2:22", false},
		{"tcp:127.0.0.1:*", "tcp:localhost:22", false},

		// IPv6: brackets are literal, and exact IPs compare by value.
		{"tcp:[::1]:*", "tcp:[::1]:22", true},
		{"tcp:[::1]:*", "tcp:[0:0::1]:22", true},
		{"tcp:[::1]:*", "tcp:1:22", false},
		{"tcp:[::1]:*", "tcp:[::2]:22", false},

		// Ports are numbers in range, spelled canonically.
		{"tcp:localhost:*", "tcp:localhost:ssh", false},
		{"tcp:localhost:*", "tcp:localhost:0", false},
		{"tcp:localhost:*", "tcp:localhost:65536", false},
		{"tcp:localhost:*", "tcp:localhost:022", false},

		// Unix paths must be clean; a wildcard can't be "..".
		{"unix:/run/*/app.sock", "unix:/run/../app.sock", false},
		{"unix:/run/app/*", "unix:/run/app/..", false},
		{"unix:/run/app/*.sock", "unix:/run/app//a.sock", false},
		{"unix:/run/app/*.sock", "unix:/run/app/sub/a.sock", false},
		{"unix:*/app.sock", "unix:../app.sock", false},
		{"unix:*/app.sock", "unix:x/app.sock", false},

		// exec: is exact, and wildcard exec patterns match nothing.
		{"exec:cat", "exec:cat /etc/hosts", false},
		{"exec:echo *", "exec:echo hi", false},
		{"exec:echo *", "exec:echo hi; echo there", false},

		// Kinds must agree, and listening targets are never allowed.
		{"tcp:localhost:*", "tls:localhost:443", false},
		{"tcp:localhost:*", "tcp-listen:22", false},
		{"tcp:localhost:*", "garbage", false},
	} {
		assert.Equal(t, tc.want, Match([]string{tc.pattern}, tc.target), "%s vs %s", tc.pattern, tc.target)
	}
}

func TestValidatePattern(t *testing.T) {
	pathStyle(t, false)
	for _, ok := range []string{"tcp:localhost:*", "tcp:[::1]:22", "unix:/run/*.sock", "exec:cat", "stdio", "tls:*:443"} {
		assert.NoError(t, ValidatePattern(ok), ok)
	}
	for _, bad := range []string{"unix:*/app.sock", "unix:run/app.sock", "exec:echo *", "exec:ls ?", "tcp-listen:22", "tcp:localhost:ssh", "nonsense", "tcp:localhost"} {
		assert.Error(t, ValidatePattern(bad), bad)
	}
}

func TestGlob(t *testing.T) {
	assert.True(t, glob("a*b*c", "axxbyyc", 0))
	assert.False(t, glob("a*b*c", "axxbyy", 0))
	assert.True(t, glob("*", "", '.'))
	assert.False(t, glob("*", "a.b", '.'))
	assert.True(t, glob("*.*", "a.b", '.'))
	assert.False(t, glob("?", "", 0))
	assert.False(t, glob("a?c", "a.c", '.'))
	// Backtracking stays bounded (O(n·m)) on a pathological input.
	long := make([]byte, 4096)
	for i := range long {
		long[i] = 'a'
	}
	assert.False(t, glob("*a*a*a*a*a*a*a*a*b", string(long), 0))
}

func TestAbstractSocketNames(t *testing.T) {
	pathStyle(t, false)
	saved := abstractSockets
	defer func() { abstractSockets = saved }()

	abstractSockets = true // Linux
	assert.True(t, Match([]string{"unix:@xumcat-*"}, "unix:@xumcat-1"))
	assert.False(t, Match([]string{"unix:@app/*/*"}, "unix:@app/../private.sock"), "no .. even in abstract names")
	assert.False(t, Match([]string{"unix:@app/*"}, "unix:@app//x"))

	abstractSockets = false // elsewhere '@' is a relative path
	assert.False(t, Match([]string{"unix:@xumcat-*"}, "unix:@xumcat-1"))
	assert.False(t, Match([]string{"unix:@app/*/*"}, "unix:@app/../private.sock"))
	assert.Error(t, ValidatePattern("unix:@xumcat-*"))
}

// pathStyle makes unix: paths follow Unix (false) or Windows (true) rules
// for the rest of the test, whatever the host system.
func pathStyle(t *testing.T, windows bool) {
	saved := windowsPaths
	windowsPaths = windows
	t.Cleanup(func() { windowsPaths = saved })
}

func TestWindowsSocketPaths(t *testing.T) {
	pathStyle(t, true)
	for _, ok := range []string{`unix:C:\run\*.sock`, `unix:c:\Users\me\app.sock`, `unix:D:\*`} {
		assert.NoError(t, ValidatePattern(ok), ok)
	}
	for _, bad := range []string{"unix:/run/*.sock", `unix:run\app.sock`, `unix:\\server\share\a.sock`, `unix:?:\a.sock`, `unix:C:a.sock`, "unix:@name"} {
		assert.Error(t, ValidatePattern(bad), bad)
	}
	for _, tc := range []struct {
		pattern, target string
		want            bool
	}{
		{`unix:C:\run\*.sock`, `unix:C:\run\a.sock`, true},
		{`unix:C:\run\app\*`, `unix:C:\run\app\x`, true},
		{`unix:C:\run\*.sock`, `unix:C:\run\..hidden.sock`, true}, // a name, not ".."
		// A wildcard stays within one segment, and '/' is not a separator.
		{`unix:C:\run\*.sock`, `unix:C:\run\sub\a.sock`, false},
		{`unix:C:\run\*.sock`, `unix:C:\run\sub/a.sock`, false},
		{`unix:C:\run\*`, `unix:C:\run\..`, false},
		{`unix:C:\run\*\a.sock`, `unix:C:\run\..\a.sock`, false},
		{`unix:C:\run\*\a.sock`, `unix:C:\run\.\a.sock`, false},
		{`unix:C:\run\*.sock`, `unix:C:\run\\a.sock`, false},
		// Segments Windows would rewrite, and alternate data streams.
		{`unix:C:\run\*`, `unix:C:\run\a.`, false},
		{`unix:C:\run\*`, `unix:C:\run\a `, false},
		{`unix:C:\run\*\a.sock`, `unix:C:\run\... \a.sock`, false},
		{`unix:C:\run\*`, `unix:C:\run\a.sock:stream`, false},
		{`unix:C:\run\*`, `unix:C:\run\`, false},
		// Unix-style paths are relative to the current drive: refused.
		{`unix:C:\run\*`, "unix:/run/a.sock", false},
		// Patterns are case-sensitive, so a differently cased target is
		// refused rather than allowed.
		{`unix:C:\run\*.sock`, `unix:c:\run\a.sock`, false},
	} {
		assert.Equal(t, tc.want, Match([]string{tc.pattern}, tc.target), "%s vs %s", tc.pattern, tc.target)
	}
}
