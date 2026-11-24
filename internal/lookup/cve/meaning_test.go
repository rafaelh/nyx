package cve

import "testing"

func TestMeaning(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		status  int
		message string
		body    string
		want    Answer
	}{
		{"401 is a refused key", 401, "", "", KeyRefused},
		{"403 naming the key", 403, "Invalid apiKey.", "", KeyRefused},
		{"403 naming the key in the body, any case", 403, "", `{"error":"bad APIKEY"}`, KeyRefused},
		{"404 naming the key", 404, "Invalid apiKey.", "", KeyRefused},
		{"404 not naming the key is nothing", 404, "", "", Other},
		{"403 without the key is a rate limit", 403, "", "", RateLimited},
		{"429 is a rate limit", 429, "", "", RateLimited},
		{"500 is nothing", 500, "oops", "", Other},
		{"400 naming the key is nothing", 400, "apiKey", "", Other},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := Meaning(tt.status, tt.message, []byte(tt.body)); got != tt.want {
				t.Errorf("Meaning(%d, %q, %q) = %d, want %d", tt.status, tt.message, tt.body, got, tt.want)
			}
		})
	}
}
