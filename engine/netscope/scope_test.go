package netscope

import "testing"

func TestNormalizeHost(t *testing.T) {
	if got := NormalizeHost("https://api.wrike.com:443/tasks"); got != "api.wrike.com" {
		t.Fatalf("NormalizeHost(url)=%q want api.wrike.com", got)
	}
	if got := NormalizeHost("api.wrike.com:443"); got != "api.wrike.com" {
		t.Fatalf("NormalizeHost(host:port)=%q want api.wrike.com", got)
	}
}

func TestEffectiveDomain(t *testing.T) {
	tests := []struct {
		host string
		want string
	}{
		{host: "news.google.com", want: "google.com"},
		{host: "raw.githubusercontent.com", want: "githubusercontent.com"},
		{host: "example.com", want: "example.com"},
		{host: "localhost", want: "localhost"},
	}
	for _, tt := range tests {
		if got := EffectiveDomain(tt.host); got != tt.want {
			t.Fatalf("EffectiveDomain(%q)=%q want %q", tt.host, got, tt.want)
		}
	}
}
