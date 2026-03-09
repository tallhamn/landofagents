package classify

import (
	"net/url"
	"strings"
)

// extractResource extracts the resource identifier from a command based on
// the extractor name. Returns empty string for unknown extractors.
func extractResource(extractor, segment string) string {
	switch extractor {
	case "first_arg":
		fields := strings.Fields(segment)
		if len(fields) >= 2 {
			return fields[len(fields)-1]
		}
	case "domain_from_url":
		return domainFromCommand(segment)
	case "url_from_curl_args":
		return domainFromCommand(segment)
	case "recipient_from_gam_args":
		fields := strings.Fields(segment)
		for i, f := range fields {
			if f == "sendemail" && i+1 < len(fields) {
				return fields[i+1]
			}
		}
	}
	return ""
}

// domainFromCommand tries to extract a domain from URLs in the command.
func domainFromCommand(segment string) string {
	for _, field := range strings.Fields(segment) {
		if strings.HasPrefix(field, "http://") || strings.HasPrefix(field, "https://") {
			if u, err := url.Parse(field); err == nil {
				return u.Hostname()
			}
		}
	}
	return ""
}
