package web

import (
	"slices"
	"strings"
	"testing"
)

func TestExtractIdentifiers_Contexts(t *testing.T) {
	t.Parallel()
	for _, c := range []struct {
		name      string
		body      string
		analytics []string
		pixels    []string
	}{
		{"gtag script", `<script async src="https://www.googletagmanager.com/gtag/js?id=G-ABC123DEF4"></script>`, []string{"G-ABC123DEF4"}, nil},
		{"gtag script with more parameters", `<script src="/gtag/js?id=UA-12345678-1&amp;l=dataLayer"></script>`, []string{"UA-12345678-1"}, nil},
		{"gtag config", `<script>gtag('config', 'G-ZZZ999YYY8');</script>`, []string{"G-ZZZ999YYY8"}, nil},
		{"gtag config double quotes and spacing", `<script>gtag( "config" ,"UA-1111111-22" )</script>`, []string{"UA-1111111-22"}, nil},
		{"gtm loader", `<script src="https://www.googletagmanager.com/gtm.js?id=GTM-ABCD123"></script>`, []string{"GTM-ABCD123"}, nil},
		{"gtm snippet", `<script>(function(w,d,s,l,i){w[l]=w[l]||[];})(window,document,'script','dataLayer','GTM-WXYZ789');</script>`, []string{"GTM-WXYZ789"}, nil},
		{"gtm noscript", `<noscript><iframe src="https://www.googletagmanager.com/ns.html?id=GTM-NS12345" height="0"></iframe></noscript>`, []string{"GTM-NS12345"}, nil},
		{"facebook init", `<script>fbq('init', '123456789012345');fbq('track', 'PageView');</script>`, nil, []string{"123456789012345"}},
		{"facebook init double quotes", `<script>fbq("init","987654321098765")</script>`, nil, []string{"987654321098765"}},
		{"facebook noscript image", `<noscript><img src="https://www.facebook.com/tr?id=555666777888999&ev=PageView&noscript=1"/></noscript>`, nil, []string{"555666777888999"}},
		{"two of each, repeated, sorted", `gtag('config','G-BBBBBB1');gtag('config','G-AAAAAA1');gtag('config','G-BBBBBB1');
			fbq('init','222222222');fbq('init','111111111');`, []string{"G-AAAAAA1", "G-BBBBBB1"}, []string{"111111111", "222222222"}},
	} {
		t.Run(c.name, func(t *testing.T) {
			a, p := extractIdentifiers([]byte(c.body))
			if !slices.Equal(a, c.analytics) || !slices.Equal(p, c.pixels) {
				t.Errorf("analytics = %v, pixels = %v; want %v, %v", a, p, c.analytics, c.pixels)
			}
		})
	}
}

// Text that looks like an identifier but is not in one of the contexts, or is
// not shaped like one, is not recorded.
func TestExtractIdentifiers_NearMisses(t *testing.T) {
	t.Parallel()
	for name, body := range map[string]string{
		"bare analytics id in text":      `<p>Our tracking code is UA-12345678-1 and G-ABC123DEF4.</p>`,
		"bare gtm id":                    `<p>GTM-ABCD123</p>`,
		"gtag script with a word":        `<script src="/gtag/js?id=analytics"></script>`,
		"gtag config with a word":        `<script>gtag('config', 'enabled');</script>`,
		"gtag event not config":          `<script>gtag('event', 'G-ABC123DEF4');</script>`,
		"gtag id not after the query id": `<script src="/gtag/js?l=dataLayer&other=G-ABC123DEF4"></script>`,
		"lower case id":                  `<script src="/gtag/js?id=g-abc123def4"></script>`,
		"gtag id longer than an id":      `<script src="/gtag/js?id=G-ABCDEFGHIJKLMNOP"></script>`,
		"gtag id with a lower-case tail": `<script src="/gtag/js?id=G-ABC123DEF4abc"></script>`,
		"facebook tr with a long number": `<img src="https://www.facebook.com/tr?id=123456789012345678901234"/>`,
		"fbq track":                      `<script>fbq('track', '123456789012345');</script>`,
		"fbq init with a word":           `<script>fbq('init', 'abc');</script>`,
		"fbq init with a short number":   `<script>fbq('init', '12');</script>`,
		"facebook tr with a word":        `<img src="https://www.facebook.com/tr?id=abc&ev=PageView"/>`,
		"facebook other path":            `<a href="https://www.facebook.com/profile?id=123456789012345">us</a>`,
		"plain number":                   `<p>Order 123456789012345</p>`,
		"nothing":                        ``,
	} {
		t.Run(name, func(t *testing.T) {
			if a, p := extractIdentifiers([]byte(body)); len(a) != 0 || len(p) != 0 {
				t.Errorf("analytics = %v, pixels = %v; want none", a, p)
			}
		})
	}
}

func copyrightOf(t *testing.T, body string) string {
	t.Helper()
	pg, ok := parsePage([]byte(body))
	if !ok {
		t.Fatal("unparsable page")
	}
	return pg.copyright()
}

func TestCopyright_FirstMatchingLineOfVisibleText(t *testing.T) {
	t.Parallel()
	for name, c := range map[string]struct{ body, want string }{
		"symbol and year":                    {`<body><footer>© 2026 Acme Pty Ltd</footer></body>`, "© 2026 Acme Pty Ltd"},
		"copyright word":                     {`<body><p>Copyright © 2019-2026 Acme Pty Ltd. All rights reserved.</p></body>`, "Copyright © 2019-2026 Acme Pty Ltd. All rights reserved."},
		"(c) and year":                       {`<body><p>Site (c) 2024 Acme</p></body>`, "Site (c) 2024 Acme"},
		"(C) upper case":                     {`<body><p>(C) 2024 Acme</p></body>`, "(C) 2024 Acme"},
		"first of two":                       {`<body><p>© 2020 First</p><p>© 2021 Second</p></body>`, "© 2020 First"},
		"inline elements join into one line": {`<body><div>© 2026 <a href="/">Acme</a> <b>Pty</b> Ltd</div></body>`, "© 2026 Acme Pty Ltd"},
		"whitespace collapsed":               {"<body><p>©   2026 \n\t Acme</p></body>", "© 2026 Acme"},
		"after another line":                 {`<body><p>Welcome</p><p>Contact us</p><p>© 2022 Acme</p></body>`, "© 2022 Acme"},
		"entity":                             {`<body><p>&copy; 2026 Acme</p></body>`, "© 2026 Acme"},
		"br breaks the line":                 {`<body><p>Welcome<br>© 2026 Acme</p></body>`, "© 2026 Acme"},
		"year after the holder":              {`<body><footer>© Acme Pty Ltd 2026</footer></body>`, "© Acme Pty Ltd 2026"},
		"(c), holder, then year":             {`<body><p>(c) Acme 2019-2026. All rights reserved.</p></body>`, "(c) Acme 2019-2026. All rights reserved."},
	} {
		t.Run(name, func(t *testing.T) {
			if got := copyrightOf(t, c.body); got != c.want {
				t.Errorf("copyright = %q, want %q", got, c.want)
			}
		})
	}
}

func TestCopyright_NotTheseLines(t *testing.T) {
	t.Parallel()
	for name, body := range map[string]string{
		"symbol without a year":     `<body><p>© Acme Pty Ltd</p></body>`,
		"year without a symbol":     `<body><p>Founded in 2019 by Acme</p></body>`,
		"year before the symbol":    `<body><p>2026 © Acme</p></body>`,
		"(c) in a list of clauses":  `<body><p>(c) the party must pay</p></body>`,
		"only in a script":          `<body><script>var s = "© 2026 Acme";</script></body>`,
		"only in a style":           `<head><style>/* © 2026 Acme */</style></head><body></body>`,
		"only in a comment":         `<body><!-- © 2026 Acme --><p>Hello</p></body>`,
		"only in the title":         `<head><title>© 2026 Acme</title></head><body><p>Hello</p></body>`,
		"only in a noscript":        `<body><noscript>© 2026 Acme</noscript></body>`,
		"a year that is not a year": `<body><p>© 3026 Acme</p></body>`,
		"year on the next line":     `<body><p>© Acme</p><p>Since 2019</p></body>`,
		"digits that hold no year":  `<body><p>© Acme ABN 12345 678</p></body>`,
		"nothing":                   ``,
	} {
		t.Run(name, func(t *testing.T) {
			if got := copyrightOf(t, body); got != "" {
				t.Errorf("copyright = %q, want none", got)
			}
		})
	}
}

// The line is cut to 120 characters (not bytes), and terminal-acting characters are removed.
func TestCopyright_CutAndSanitised(t *testing.T) {
	t.Parallel()
	long := "© 2026 " + strings.Repeat("é", 200)
	got := copyrightOf(t, "<body><p>"+long+"</p></body>")
	if n := len([]rune(got)); n != 120 || !strings.HasPrefix(got, "© 2026 éé") {
		t.Errorf("copyright has %d characters: %q, want the first 120", n, got)
	}
	exact := "© 2026 " + strings.Repeat("a", 113) // 120 characters
	if got := copyrightOf(t, "<body><p>"+exact+"</p></body>"); got != exact {
		t.Errorf("a line of exactly 120 characters was changed: %q", got)
	}
	got = copyrightOf(t, "<body><p>© 2026 Ac\x1b[31mme\x07 Ltd</p></body>")
	if strings.ContainsAny(got, "\x1b\x07") || !strings.HasPrefix(got, "© 2026 Ac") {
		t.Errorf("copyright = %q, want the escape and bell characters removed", got)
	}
}

// MurmurHash3 (x86, 32 bit, seed 0) against published test vectors.
func TestMurmur3_PublishedVectors(t *testing.T) {
	t.Parallel()
	for _, c := range []struct {
		in   string
		want uint32
	}{
		{"", 0},
		{"test", 0xba6bd213},
		{"abc", 0xb3dd93fa},
		{"The quick brown fox jumps over the lazy dog", 0x2e4ff723},
	} {
		if got := murmur3([]byte(c.in), 0); got != c.want {
			t.Errorf("murmur3(%q) = %#x, want %#x", c.in, got, c.want)
		}
	}
	if got := murmur3([]byte("aaaa"), 0x9747b28c); got != 0x5a97808a {
		t.Errorf("murmur3(aaaa, seed) = %#x, want 0x5a97808a", got)
	}
}

// Favicon hash fixtures were computed independently using Python-style base64 and a separate
// MurmurHash3 implementation.
func TestFaviconHash_KnownValues(t *testing.T) {
	t.Parallel()
	body100 := make([]byte, 100) // base64 is longer than 76 characters, so it has an inner line break
	for i := range body100 {
		body100[i] = byte(i)
	}
	for _, c := range []struct {
		name string
		body []byte
		want int32
	}{
		{"empty file", nil, 0},
		{"three bytes", []byte("abc"), -868969266},
		{"hundred bytes across a line break", body100, -1165240594},
	} {
		if got := FaviconHash(c.body); got != c.want {
			t.Errorf("%s: FaviconHash = %d, want %d", c.name, got, c.want)
		}
	}
}
