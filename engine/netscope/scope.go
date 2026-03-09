package netscope

import (
	"net"
	"net/url"
	"strings"

	"golang.org/x/net/publicsuffix"
)

// NormalizeHost trims, lowercases, and strips scheme/port from a resource host.
func NormalizeHost(resource string) string {
	host := strings.TrimSpace(strings.ToLower(resource))
	if host == "" {
		return ""
	}
	if strings.Contains(host, "://") {
		if parsed, err := url.Parse(host); err == nil && parsed.Hostname() != "" {
			host = strings.ToLower(parsed.Hostname())
		}
	}
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	return host
}

// EffectiveDomain resolves the registrable domain for host and falls back to
// a parent-domain heuristic for private suffixes.
func EffectiveDomain(host string) string {
	if host == "" {
		return ""
	}
	domain, err := publicsuffix.EffectiveTLDPlusOne(host)
	if err == nil {
		domain = strings.ToLower(domain)
		if domain != host {
			return domain
		}
	}
	return broadDomainByParent(host)
}

func broadDomainByParent(host string) string {
	parts := strings.Split(host, ".")
	if len(parts) < 3 {
		return host
	}
	parent := strings.Join(parts[1:], ".")
	if parent == "" {
		return host
	}
	etld1, err := publicsuffix.EffectiveTLDPlusOne(parent)
	if err == nil && strings.ToLower(etld1) == strings.ToLower(parent) {
		return strings.ToLower(parent)
	}
	suffix, icann := publicsuffix.PublicSuffix(parent)
	if strings.ToLower(suffix) == strings.ToLower(parent) && !icann {
		// Private-suffix parent fallback (e.g. githubusercontent.com).
		return strings.ToLower(parent)
	}
	return host
}
