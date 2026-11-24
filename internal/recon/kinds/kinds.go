// Package kinds defines typed record handles and their attributes, visibility and output rules.
// Procedures create observations and readers decode records through the same handle. Attribute JSON
// names are stored in engagement databases, so renaming them breaks existing state.
package kinds

import (
	"encoding/json"
	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/rafaelh/nyx/internal/recon/inventory"
	"github.com/rafaelh/nyx/internal/recon/store"
	"github.com/rafaelh/nyx/internal/scope"
)

// Kind describes how the records of a kind are shown.
type Kind struct {
	Name string
	// Singular labels console events; Category names the summary count. Entity categories
	// apply only to in-scope records and are empty for uncounted inputs.
	Singular, Category string
	// place classifies entity records by key as in scope, candidate or excluded. It returns
	// false for stored entities that should not be listed.
	place func(sc *scope.Scope, inv *inventory.Inventory, key string) (scope.Class, bool)
	// Printed enables a found line on a record's first engagement sighting.
	Printed bool
	// HostAttr identifies a web record's host attribute. Visibility is checked against the
	// current scope when read.
	HostAttr string
	// PortKey identifies address/port keys. Records are visible only while their address
	// remains eligible for port checks.
	PortKey bool
	// ClosedHides marks third-party port reports superseded by nyx's own checks. Confirmed
	// closed ports are hidden; confirmed open ports are counted through open_port instead.
	ClosedHides bool
	// HostKey identifies hostname keys, whose records are visible only while that name is
	// in scope.
	HostKey bool
	// OutsideAttr adds a requirement that the named domain be outside scope. An empty
	// domain qualifies. Other visibility rules still apply.
	OutsideAttr string
	// Found adds fields to a new record's event, optionally replacing category and value.
	// Its text field supplies the console text after "+".
	Found func(store.Record) map[string]any
	// Change labels rows in changes.csv. Kinds sharing an output row share a label;
	// evidence and internal kinds have none. Entity records use their candidate or excluded
	// placement label when applicable, otherwise their in-scope Change label.
	Change string
	// fromKey, set for Keyed kinds, returns a record's attributes with the identifying fields its
	// key carries filled in, so the showing rule applies to a non-current record too.
	fromKey func(store.Record) map[string]any
}

// Entity reports whether this kind uses scope placement rather than ordinary shown/hidden
// visibility.
func (k Kind) Entity() bool { return k.place != nil }

// scoped reports whether showing a record of k depends on the scope.
func (k Kind) scoped() bool {
	return k.Entity() || k.HostAttr != "" || k.PortKey || k.HostKey || k.OutsideAttr != ""
}

// Shared changes.csv labels for entity placements and counted record kinds.
const (
	LabelHostname   = "hostname"
	LabelCandidate  = "candidate"
	LabelExcluded   = "excluded"
	LabelNetblock   = "netblock"
	LabelFinding    = "finding"
	LabelAddress    = "address"
	LabelWebService = "web service"
	LabelOpenPort   = "open port"
)

// Summary categories of entity kinds.
const (
	Hosts      = "hosts"
	Netblocks  = "netblocks"
	Candidates = "candidates"
	Excluded   = "excluded"
)

// Named is a kind handle: an Of, a Bare, or one found by Lookup.
type Named interface {
	Name() string
	kind() Kind
}

// ref provides the shared identity and Named methods for kind handles.
type ref struct{ k Kind }

// Name returns the stored record-kind identifier.
func (r ref) Name() string { return r.k.Name }

func (r ref) kind() Kind { return r.k }

// Of is a typed record handle for attributes A. Use the registered handles in table.go; the
// zero value is invalid.
type Of[A any] struct{ ref }

// Obs is an observation of the kind.
func (k Of[A]) Obs(key string, a A) store.Obs {
	return store.Obs{Kind: k.k.Name, Key: key, Attrs: encode(a)}
}

// Attrs decodes merged stored attributes. Values incompatible with a field's type become zero
// values, allowing records from older schemas to be read.
func (k Of[A]) Attrs(r store.Record) A {
	var a A
	if len(r.Attrs) > 0 {
		decode(r.Attrs, &a)
	}
	return a
}

// Keyed constructs record keys from attributes so the two cannot disagree. When reading, it can
// also recover missing attributes from the key.
type Keyed[A any] struct {
	Of[A]
	key func(A) string
	// rebuild fills in the empty fields of *a that key carries.
	rebuild func(key string, a *A)
}

// Key builds a record key from its identifying attributes; unrelated fields may be empty.
func (k Keyed[A]) Key(a A) string { return k.key(a) }

// Obs is the observation of a record with attributes a, under its Key.
func (k Keyed[A]) Obs(a A) store.Obs { return k.Of.Obs(k.key(a), a) }

// Attrs decodes attributes and recovers missing identifying fields from the key. This also
// supports non-current records, whose current-observation attributes are gone.
func (k Keyed[A]) Attrs(r store.Record) A {
	a := k.Of.Attrs(r)
	k.rebuild(r.Key, &a)
	return a
}

// Bare is the handle of a kind whose observations carry no attributes.
type Bare struct{ ref }

// Obs is an observation of the kind.
func (k Bare) Obs(key string) store.Obs { return store.Obs{Kind: k.k.Name, Key: key} }

// encode produces the map representation used by the store, including float64 numbers and []any
// lists.
func encode(a any) map[string]any {
	b, err := json.Marshal(a)
	if err != nil {
		panic(fmt.Sprintf("kinds: attributes %T do not encode: %v", a, err)) // a programming error
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		panic(fmt.Sprintf("kinds: attributes %T are not an object: %v", a, err))
	}
	return m
}

var table []Kind // sorted by name once the handles are defined

func define[A any](k Kind) Of[A] { table = append(table, k); return Of[A]{ref{k}} }

// defineKeyed registers key construction and recovery of missing attributes from stored keys.
func defineKeyed[A any](k Kind, key func(A) string, rebuild func(key string, a *A)) Keyed[A] {
	k.fromKey = func(r store.Record) map[string]any {
		var a A
		if len(r.Attrs) > 0 {
			decode(r.Attrs, &a)
		}
		rebuild(r.Key, &a)
		return encode(a)
	}
	table = append(table, k)
	return Keyed[A]{Of: Of[A]{ref{k}}, key: key, rebuild: rebuild}
}

// defineJoined registers a key made by joining selected fields with "|", with matching field
// recovery.
func defineJoined[A any](k Kind, fields func(*A) []*string) Keyed[A] {
	return defineKeyed(k,
		func(a A) string {
			parts := fields(&a)
			s := make([]string, len(parts))
			for i, p := range parts {
				s[i] = *p
			}
			return strings.Join(s, "|")
		},
		func(key string, a *A) { fillFromKey(key, fields(a)...) })
}

// fillFromKey fills empty destinations from a "|"-joined key. The last field takes the
// remainder, allowing bars in TXT values. Too few parts leaves all fields unchanged.
func fillFromKey(key string, dst ...*string) {
	if !slices.ContainsFunc(dst, func(p *string) bool { return *p == "" }) {
		return
	}
	parts := strings.SplitN(key, "|", len(dst))
	if len(parts) != len(dst) {
		return
	}
	for i, p := range dst {
		if *p == "" {
			*p = parts[i]
		}
	}
}

func defineBare(k Kind) Bare { table = append(table, k); return Bare{ref{k}} }

func init() {
	slices.SortFunc(table, func(a, b Kind) int { return strings.Compare(a.Name, b.Name) })
}

// Get returns a kind by name.
func Get(name string) (Kind, bool) {
	i, ok := slices.BinarySearchFunc(table, name, func(k Kind, n string) int { return strings.Compare(k.Name, n) })
	if !ok {
		return Kind{}, false
	}
	return table[i], true
}

// handle supports generic kind reads but cannot construct observations.
type handle struct{ ref }

// Lookup resolves a kind by name for generic readers using All and Visibility.
func Lookup(name string) (Named, bool) {
	k, ok := Get(name)
	return handle{ref{k}}, ok
}

// All returns every kind sorted by name.
func All() []Kind { return slices.Clone(table) }

// Size formats byte counts, adding "+" for truncated bodies of unknown total size. Exact counts
// remain numeric.
type Size string

// SizeOf is an exact size.
func SizeOf(n int64) Size { return Size(strconv.FormatInt(n, 10)) }

func (s Size) MarshalJSON() ([]byte, error) {
	// JSON numbers require canonical integers, excluding accepted-but-noncanonical forms
	// such as +5 or 007.
	if n, err := strconv.ParseInt(string(s), 10, 64); err == nil && strconv.FormatInt(n, 10) == string(s) {
		return []byte(s), nil
	}
	return json.Marshal(string(s))
}

func (s *Size) UnmarshalJSON(b []byte) error {
	var str string
	if err := json.Unmarshal(b, &str); err == nil {
		*s = Size(str)
		return nil
	}
	var n json.Number
	if err := json.Unmarshal(b, &n); err != nil {
		return err
	}
	*s = Size(n.String())
	return nil
}
