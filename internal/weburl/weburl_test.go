package weburl

import "testing"

func TestNormaliseURLCanonicalisesIPLiteralsAndPorts(t *testing.T) {
	t.Parallel()
	for raw, want := range map[string]string{
		"http://[2001:db8:0:0::1]:8080/x": "http://[2001:db8::1]:8080/x",
		"http://[2001:DB8::1]/":           "http://[2001:db8::1]/",
		"http://[::ffff:192.0.2.1]/":      "http://192.0.2.1/",
		"http://a.com:080/":               "http://a.com/",
		"https://a.com:0443":              "https://a.com/",
		"http://a.com:08080/p":            "http://a.com:8080/p",
	} {
		if got, ok := NormaliseURL(raw); !ok || got != want {
			t.Errorf("NormaliseURL(%q) = %q, %v; want %q", raw, got, ok, want)
		}
	}
	for _, raw := range []string{"http://a.com:0/", "http://a.com:65536/"} {
		if got, ok := NormaliseURL(raw); ok {
			t.Errorf("NormaliseURL(%q) = %q, want rejected", raw, got)
		}
	}
}
