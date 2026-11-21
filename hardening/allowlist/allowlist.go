package allowlist

import (
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync/atomic"
)

// Allowlist constrains CONTROL-PLANE egress (the LLM provider, web search,
// notifications, the archive store, MCP servers, update checks) to an
// operator-approved set of hosts. It is a defense-in-depth guarantee for the
// operator's stated goal: "nothing in this program may talk to a host I did
// not approve."
//
// It is OFF by default, so an unconfigured deployment behaves exactly as before.
// Two environment variables turn it on:
//
//	ARTEX_EGRESS_MODE   off | audit | enforce      (default off; an unknown value enforces)
//	ARTEX_EGRESS_ALLOW  comma/space list of hosts  (e.g. "api.anthropic.com,127.0.0.1")
//
// A host entry matches the request host exactly, or as a parent domain:
// "anthropic.com" admits "api.anthropic.com" but not "evil-anthropic.com".
//
// Scope boundary: this is NOT the data-plane target gate. Scanning a pentest
// target is governed separately by intercept.PinnedDialer plus the task's
// target scope; the allowlist deliberately leaves that path untouched, because
// a scanner's targets are arbitrary by design. The allowlist only covers the
// fixed, operator-owned clients that carry the operator's own data outward.
//
// It is a host-level check made where the destination host is known (the HTTP
// round trip, or just before a dial). It is not a network firewall: a shell
// command the agent runs is outside it. Confine the process (container network
// policy) for that.
type Allowlist struct {
	mode  egressMode
	hosts []string // normalized; matched exactly or as a parent domain
}

type egressMode int

const (
	modeOff egressMode = iota
	modeAudit
	modeEnforce
)

// Environment variable names (exported so callers and docs reference one source).
const (
	EgressModeEnv  = "ARTEX_EGRESS_MODE"
	EgressAllowEnv = "ARTEX_EGRESS_ALLOW"
)

// activeAllowlist holds the process-wide allowlist. It is loaded from the
// environment on first use (no init function: nothing in this package runs at
// import time) and is replaceable in tests. An atomic pointer so reads never
// race a reload.
var activeAllowlist atomic.Pointer[Allowlist]

// LoadAllowlist builds an Allowlist from the environment. An unset or "off" mode
// yields a disabled allowlist that admits every host.
func LoadAllowlist() *Allowlist {
	return ParseAllowlist(os.Getenv(EgressModeEnv), os.Getenv(EgressAllowEnv))
}

// ParseAllowlist builds an Allowlist from an explicit mode and host list.
//
// An empty mode is off. A mode that is set but not recognized ENFORCES: a typo
// such as "enfroce" must not silently leave the operator unprotected, and an
// allowlist that blocks is noticed at once while one that is quietly off is not.
func ParseAllowlist(mode, allow string) *Allowlist {
	a := &Allowlist{mode: parseMode(mode)}
	sep := func(r rune) bool { return r == ',' || r == ' ' || r == '\t' || r == '\n' || r == '\r' }
	for _, raw := range strings.FieldsFunc(allow, sep) {
		// ".anthropic.com" and "anthropic.com" are the same rule.
		if h := normalizeHost(strings.TrimPrefix(strings.TrimSpace(raw), ".")); h != "" {
			a.hosts = append(a.hosts, h)
		}
	}
	return a
}

func parseMode(s string) egressMode {
	switch v := strings.ToLower(strings.TrimSpace(s)); v {
	case "", "off", "0", "false", "no", "disabled":
		return modeOff
	case "audit", "log", "warn":
		return modeAudit
	case "enforce", "block", "on", "1", "true", "yes":
		return modeEnforce
	default:
		log.Printf("[egress] %s=%q is not a known mode (off|audit|enforce); enforcing", EgressModeEnv, v)
		return modeEnforce
	}
}

// normalizeHost lowercases a host and drops the brackets of an IPv6 literal and
// the trailing dot of a fully qualified name, so "API.Anthropic.com." and
// "api.anthropic.com" are one host.
func normalizeHost(h string) string {
	h = strings.ToLower(strings.TrimSpace(h))
	h = strings.TrimSuffix(strings.TrimPrefix(h, "["), "]")
	return strings.TrimSuffix(h, ".")
}

// ActiveAllowlist returns the process-wide allowlist (never nil), loading it
// from the environment on first use.
func ActiveAllowlist() *Allowlist {
	if a := activeAllowlist.Load(); a != nil {
		return a
	}
	a := LoadAllowlist()
	if !activeAllowlist.CompareAndSwap(nil, a) {
		return activeAllowlist.Load()
	}
	return a
}

// SetActiveAllowlist replaces the process-wide allowlist and returns the
// previous one, so a test can restore it with a deferred call.
func SetActiveAllowlist(a *Allowlist) *Allowlist {
	if a == nil {
		a = &Allowlist{}
	}
	return activeAllowlist.Swap(a)
}

// String describes the allowlist for a log line.
func (a *Allowlist) String() string {
	if !a.Enabled() {
		return "off"
	}
	mode := "enforce"
	if a.mode == modeAudit {
		mode = "audit"
	}
	return fmt.Sprintf("mode=%s hosts=[%s]", mode, strings.Join(a.hosts, " "))
}

// Enabled reports whether the allowlist blocks or audits anything at all.
func (a *Allowlist) Enabled() bool { return a != nil && a.mode != modeOff }

// Allowed reports whether host is on the list. An empty host is never on it.
// When the allowlist is off, every host is allowed. Audit mode does not change
// the answer: Allowed says what the list holds, Check and Guard decide what to
// do about it.
func (a *Allowlist) Allowed(host string) bool {
	if a == nil || a.mode == modeOff {
		return true
	}
	host = normalizeHost(host)
	if host == "" {
		return false
	}
	for _, e := range a.hosts {
		if host == e || strings.HasSuffix(host, "."+e) {
			return true
		}
	}
	return false
}

// Check applies the allowlist to a connection that is not an HTTP round trip
// (an SMTP dial, a tool that owns its HTTP client). what names the caller for
// the log and the error. It returns nil when host is allowed, and in audit mode
// after logging.
func (a *Allowlist) Check(what, host string) error {
	if a.Allowed(host) {
		return nil
	}
	if a.mode == modeAudit {
		log.Printf("[egress] AUDIT: would block %s: host %q not in %s", what, host, EgressAllowEnv)
		return nil
	}
	return fmt.Errorf("egress: %s: host %q is not in the allowlist (%s); add it or set %s=off", what, host, EgressAllowEnv, EgressModeEnv)
}

// CheckHost applies the process-wide allowlist to host. See Allowlist.Check.
func CheckHost(what, host string) error { return ActiveAllowlist().Check(what, host) }

// CheckURL applies the process-wide allowlist to the host of rawURL. A URL that
// does not parse, or has no host, is refused while the allowlist enforces.
func CheckURL(what, rawURL string) error {
	host := ""
	if u, err := url.Parse(strings.TrimSpace(rawURL)); err == nil {
		host = u.Hostname()
	}
	return CheckHost(what, host)
}

// Guard wraps base so every request first passes the host allowlist. base nil
// means http.DefaultTransport. When the allowlist is off, base is returned
// unchanged, so there is zero overhead and zero behavior change by default.
//
// The check runs on every round trip, so each hop of a redirect is checked, and
// it reads the request URL, so it holds for a request sent through a proxy.
func (a *Allowlist) Guard(base http.RoundTripper) http.RoundTripper {
	if base == nil {
		base = http.DefaultTransport
	}
	if !a.Enabled() {
		return base
	}
	return &allowlistTransport{a: a, base: base}
}

// Guard wraps base with the process-wide allowlist, read at each request. It is
// safe for a client built once and kept (a package-level client): the allowlist
// in force when the request is sent applies.
func Guard(base http.RoundTripper) http.RoundTripper {
	if base == nil {
		base = http.DefaultTransport
	}
	return activeTransport{base}
}

type activeTransport struct{ base http.RoundTripper }

func (t activeTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	return ActiveAllowlist().Guard(t.base).RoundTrip(req)
}

type allowlistTransport struct {
	a    *Allowlist
	base http.RoundTripper
}

func (t *allowlistTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if err := t.a.Check(req.Method+" "+req.URL.Redacted(), req.URL.Hostname()); err != nil {
		return nil, err
	}
	return t.base.RoundTrip(req)
}
