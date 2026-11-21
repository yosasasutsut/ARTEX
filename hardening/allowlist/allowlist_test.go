package allowlist

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestAllowlistAllowed(t *testing.T) {
	a := ParseAllowlist("enforce", "api.anthropic.com, anthropic.com ,127.0.0.1\r\napi.openai.com .example.org ::1")
	cases := []struct {
		host string
		want bool
	}{
		{"api.anthropic.com", true},    // exact
		{"anthropic.com", true},        // exact parent
		{"eu.api.anthropic.com", true}, // subdomain of a parent entry
		{"evil-anthropic.com", false},  // suffix-string trap, not a dot-boundary match
		{"notanthropic.com", false},    // ditto
		{"anthropic.com.evil.net", false},
		{"api.openai.com", true},      // second entry
		{"openai.com", false},         // parent not listed, only the api host
		{"127.0.0.1", true},           // literal IP entry
		{"127.0.0.10", false},         // an IP is never a parent domain
		{"169.254.169.254", false},    // metadata IP never admitted unless listed
		{"", false},                   // empty host
		{"API.Anthropic.COM", true},   // case-insensitive
		{"api.anthropic.com.", true},  // trailing dot of a fully qualified name
		{"a.example.org", true},       // leading-dot entry is a parent rule
		{"example.org", true},         // and admits the parent itself
		{"::1", true},                 // IPv6 literal as url.Hostname returns it
		{"[::1]", true},               // bracketed form
		{" api.openai.com ", true},    // surrounding space
		{"api.openai.com:443", false}, // a host:port is not a host
	}
	for _, c := range cases {
		if got := a.Allowed(c.host); got != c.want {
			t.Errorf("Allowed(%q) = %v, want %v", c.host, got, c.want)
		}
	}
}

func TestAllowlistModes(t *testing.T) {
	for _, mode := range []string{"", "off", "OFF", "0", "false", "no", "disabled", "  off  "} {
		a := ParseAllowlist(mode, "only.this.host")
		if a.Enabled() {
			t.Errorf("mode %q should be disabled", mode)
		}
		if !a.Allowed("anything.example.com") {
			t.Errorf("mode %q: disabled allowlist must admit every host", mode)
		}
	}
	// A mode that is set but unknown must fail closed, not open.
	for _, mode := range []string{"enforce", "ENFORCE", "block", "on", "1", "enfroce", "nonsense"} {
		a := ParseAllowlist(mode, "only.this.host")
		if !a.Enabled() || a.mode != modeEnforce {
			t.Errorf("mode %q should enforce", mode)
		}
		if a.Check("test", "other.example.com") == nil {
			t.Errorf("mode %q: a host off the list must be refused", mode)
		}
	}
	for _, mode := range []string{"audit", "log", "warn"} {
		a := ParseAllowlist(mode, "only.this.host")
		if a.mode != modeAudit {
			t.Errorf("mode %q should audit", mode)
		}
		if err := a.Check("test", "other.example.com"); err != nil {
			t.Errorf("mode %q: audit must not refuse: %v", mode, err)
		}
	}
}

func TestEnforceWithEmptyListBlocksEverything(t *testing.T) {
	a := ParseAllowlist("enforce", "")
	if a.Allowed("api.anthropic.com") {
		t.Error("enforce with no hosts must admit nothing")
	}
}

func TestNilAllowlistIsOff(t *testing.T) {
	var a *Allowlist
	if a.Enabled() || !a.Allowed("x.example") || a.Check("t", "x.example") != nil {
		t.Error("a nil allowlist must behave as off")
	}
	if a.Guard(http.DefaultTransport) != http.DefaultTransport {
		t.Error("a nil allowlist must return the base transport")
	}
}

// target counts the requests that reach a test server.
func target(t *testing.T, h http.HandlerFunc) (*httptest.Server, *int) {
	t.Helper()
	n := new(int)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		*n++
		if h != nil {
			h(w, r)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(srv.Close)
	return srv, n
}

func TestGuardEnforceBlocks(t *testing.T) {
	srv, n := target(t, nil)

	// 127.0.0.1 (the test server) is not on the list: refused before it leaves.
	client := &http.Client{Transport: ParseAllowlist("enforce", "api.anthropic.com").Guard(http.DefaultTransport)}
	_, err := client.Get(srv.URL)
	if err == nil {
		t.Fatal("enforce: expected the request to be blocked, got nil error")
	}
	if !strings.Contains(err.Error(), "not in the allowlist") {
		t.Errorf("enforce: error should name the allowlist: %v", err)
	}
	if *n != 0 {
		t.Fatal("enforce: request reached the server despite the block")
	}

	client = &http.Client{Transport: ParseAllowlist("enforce", "127.0.0.1").Guard(http.DefaultTransport)}
	resp, err := client.Get(srv.URL)
	if err != nil {
		t.Fatalf("allowed host should pass: %v", err)
	}
	resp.Body.Close()
	if *n != 1 {
		t.Fatal("allowed host: request did not reach the server")
	}
}

// A redirect to a host off the list must be refused: the first hop is allowed,
// the second is a new round trip and is checked on its own.
func TestGuardChecksEveryRedirectHop(t *testing.T) {
	other, reachedOther := target(t, nil)
	// "localhost" and "127.0.0.1" are the same server but different hosts to the
	// allowlist, which is what a redirect to another origin looks like.
	otherURL := strings.Replace(other.URL, "127.0.0.1", "localhost", 1)
	first, reachedFirst := target(t, func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, otherURL, http.StatusFound)
	})

	client := &http.Client{Transport: ParseAllowlist("enforce", "127.0.0.1").Guard(http.DefaultTransport)}
	if _, err := client.Get(first.URL); err == nil {
		t.Fatal("a redirect to a host off the list must be refused")
	}
	if *reachedFirst != 1 || *reachedOther != 0 {
		t.Fatalf("first=%d other=%d, want 1 and 0", *reachedFirst, *reachedOther)
	}
}

// Through a proxy the connection goes to the proxy, but the allowlist reads the
// request URL, so the destination is still what is checked.
func TestGuardChecksDestinationNotProxy(t *testing.T) {
	proxy, reachedProxy := target(t, nil)
	pu, _ := url.Parse(proxy.URL)
	tr := &http.Transport{Proxy: http.ProxyURL(pu)}
	client := &http.Client{Transport: ParseAllowlist("enforce", "127.0.0.1").Guard(tr)}
	if _, err := client.Get("http://blocked.example/x"); err == nil {
		t.Fatal("destination off the list must be refused even when the proxy host is listed")
	}
	if *reachedProxy != 0 {
		t.Fatal("the request reached the proxy")
	}
}

func TestGuardAuditPassesButDoesNotBlock(t *testing.T) {
	srv, n := target(t, nil)
	client := &http.Client{Transport: ParseAllowlist("audit", "api.anthropic.com").Guard(http.DefaultTransport)}
	resp, err := client.Get(srv.URL)
	if err != nil {
		t.Fatalf("audit mode must not block: %v", err)
	}
	resp.Body.Close()
	if *n != 1 {
		t.Fatal("audit mode: request should still reach the server")
	}
}

func TestGuardOffReturnsBaseUnchanged(t *testing.T) {
	base := http.DefaultTransport
	if got := ParseAllowlist("off", "").Guard(base); got != base {
		t.Error("off mode must return the base transport unchanged (zero overhead)")
	}
}

// The package-level Guard reads the active allowlist at each request, so a
// client built before the allowlist changed follows the change.
func TestPackageGuardFollowsActiveAllowlist(t *testing.T) {
	srv, n := target(t, nil)
	prev := SetActiveAllowlist(ParseAllowlist("off", ""))
	defer SetActiveAllowlist(prev)

	client := &http.Client{Transport: Guard(nil)}
	resp, err := client.Get(srv.URL)
	if err != nil {
		t.Fatalf("off: %v", err)
	}
	resp.Body.Close()

	SetActiveAllowlist(ParseAllowlist("enforce", "api.anthropic.com"))
	if _, err := client.Get(srv.URL); err == nil {
		t.Fatal("the same client must be refused once the allowlist enforces")
	}
	if *n != 1 {
		t.Fatalf("server saw %d requests, want 1", *n)
	}
}

func TestCheckURL(t *testing.T) {
	prev := SetActiveAllowlist(ParseAllowlist("enforce", "api.tavily.com"))
	defer SetActiveAllowlist(prev)
	for raw, ok := range map[string]bool{
		"https://api.tavily.com":            true,
		"https://api.tavily.com:443/search": true,
		" https://API.tavily.com/ ":         true,
		"https://api.search.brave.com":      false,
		"https://user:pw@evil.example/":     false,
		"":                                  false,
		"not a url":                         false,
		"api.tavily.com":                    false, // no scheme: no host to check
	} {
		if err := CheckURL("test", raw); (err == nil) != ok {
			t.Errorf("CheckURL(%q) err=%v, want allowed=%v", raw, err, ok)
		}
	}
}

func TestSetActiveAllowlistRestore(t *testing.T) {
	prev := SetActiveAllowlist(ParseAllowlist("enforce", "example.com"))
	defer SetActiveAllowlist(prev)
	if ActiveAllowlist().Allowed("other.net") {
		t.Error("active allowlist not applied")
	}
	if SetActiveAllowlist(nil); ActiveAllowlist().Enabled() {
		t.Error("nil must reset to off")
	}
}

func TestActiveAllowlistLoadsFromEnv(t *testing.T) {
	t.Setenv(EgressModeEnv, "enforce")
	t.Setenv(EgressAllowEnv, "api.anthropic.com")
	prev := activeAllowlist.Swap(nil) // force a first-use load
	defer activeAllowlist.Store(prev)
	a := ActiveAllowlist()
	if !a.Enabled() || !a.Allowed("api.anthropic.com") || a.Allowed("example.com") {
		t.Errorf("allowlist not loaded from the environment: %s", a)
	}
}
