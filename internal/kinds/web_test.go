package kinds_test

import (
	"testing"

	"github.com/rafaelh/nyx/internal/kinds"
	"github.com/rafaelh/nyx/internal/store"
)

// web_service and url name the attribute holding their host so
// the summary and the CSVs filter them identically; http_port is internal.
func TestWebKinds(t *testing.T) {
	t.Parallel()
	for _, name := range []string{"web_service", "url"} {
		k, ok := kinds.Get(name)
		if !ok || k.HostAttr != "host" {
			t.Errorf("%s = %+v, want HostAttr \"host\"", name, k)
		}
	}
	if k, _ := kinds.Get("web_service"); !k.Printed {
		t.Error("web_service is printed")
	}
	if k, _ := kinds.Get("url"); k.Category == "" || k.Printed {
		t.Error("url is counted and never printed")
	}
	k, ok := kinds.Get("http_port")
	if !ok {
		t.Fatal("http_port is not registered")
	}
	if k.Category != "" || k.Printed || k.Entity {
		t.Errorf("http_port = %+v, want an internal kind with no category", k)
	}
	if k, _ := kinds.Get("open_port"); k.HostAttr != "" {
		t.Error("open_port has no host attribute")
	}
}

// web_identifier is shown while its service's host is in scope, and is internal:
// never counted or printed.
func TestWebIdentifierKind(t *testing.T) {
	t.Parallel()
	k, ok := kinds.Get("web_identifier")
	if !ok {
		t.Fatal("web_identifier is not registered")
	}
	if k.HostAttr != "host" || k.Printed || k.Entity {
		t.Errorf("web_identifier = %+v, want an internal kind shown by its host", k)
	}
	o := kinds.WebIdentifier.Obs("http://a.example.com|favicon|1", kinds.WebIdentifierAttrs{
		Service: "http://a.example.com", Host: "a.example.com", Type: kinds.IdentifierFavicon, Value: "1"})
	a := kinds.WebIdentifier.Attrs(store.Record{Kind: o.Kind, Key: o.Key, Attrs: o.Attrs})
	if a.Type != "favicon" || a.Value != "1" || a.Host != "a.example.com" {
		t.Errorf("attrs = %+v", a)
	}
}
