// Package kinds defines the record kinds: for each, its name, the attributes
// its observations carry (a struct, in table.go), and how its records are shown
// (counted in the summary, printed when found, written to the files and used to
// derive findings; see Visibility).
//
// Stages write observations through a kind's handle and readers decode records
// through the same handle, so a kind's attributes are defined once. The JSON
// names of the attribute structs are what the state database stores: renaming
// one breaks resuming an existing engagement.
package kinds

import (
	"encoding/json"
	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/rafaelh/nyx/internal/inventory"
	"github.com/rafaelh/nyx/internal/scope"
	"github.com/rafaelh/nyx/internal/store"
)

// Kind describes how the records of a kind are shown.
type Kind struct {
	Name string
	// Singular and Category are the console label of one record ("web service")
	// and the summary category ("web services"). An entity kind's Category is
	// that of a record placed in scope, and is empty when such a record is an
	// input, which is not counted.
	Singular, Category string
	// place, set on the entity kinds, places a record against the scope by its
	// key (see Visibility.Placement): in scope, as a candidate or as excluded,
	// which decides its summary category. It is not placed (false) when it stays
	// on record without being listed.
	place func(sc *scope.Scope, inv *inventory.Inventory, key string) (scope.Class, bool)
	// Printed kinds are printed as a line the first time they are seen in an engagement.
	Printed bool
	// HostAttr names the attribute holding the host of a web record. Such a
	// record is shown only while that host is in scope, decided when it is read.
	HostAttr string
	// PortKey kinds are keyed by a target address and port. Such a record is
	// shown only while that address is port-eligible, decided when it is read.
	PortKey bool
	// ClosedHides marks a PortKey kind as a third party's report of a port that
	// nyx's own handshake settles: a record is hidden once nyx found the port
	// closed, and not counted on its own once nyx found it open (open_port counts it).
	ClosedHides bool
	// HostKey kinds are keyed by a hostname. Such a record is shown only while
	// that name is in scope, decided when it is read.
	HostKey bool
	// OutsideAttr names an attribute holding a domain. A record that has one is
	// shown only while that domain is not in scope (an empty value counts as
	// outside), decided when it is read, on top of any other rule.
	OutsideAttr string
	// Found, if set, describes a new record's found line: its fields are added
	// to the found event, and its "text" is what the console prints after "+".
	Found func(store.Record) map[string]any
	// Change is the label changes.csv lists a record of the kind under, and the
	// kinds whose records share one output file row share one (a resolution and a
	// claim with one key are one row of resolutions.csv). A kind with none, an
	// evidence or internal kind, is not listed. An entity kind's Change is the
	// label of a record placed in scope; one placed as a candidate or as excluded
	// is listed under that label instead (see Visibility.ChangeLabel).
	Change string
}

// Entity reports whether records of the kind are placed against the scope
// (in scope, as a candidate or as excluded) rather than shown or hidden.
func (k Kind) Entity() bool { return k.place != nil }

// scoped reports whether showing a record of k depends on the scope.
func (k Kind) scoped() bool {
	return k.Entity() || k.HostAttr != "" || k.PortKey || k.HostKey || k.OutsideAttr != ""
}

// The changes.csv labels other packages read: those of the entity categories
// (see Visibility.ChangeLabel), and those of the kinds the summary counts.
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

// ref is what every kind handle holds, and gives it Named's methods.
type ref struct{ k Kind }

// Name is the kind's name, as the store keys its records.
func (r ref) Name() string { return r.k.Name }

func (r ref) kind() Kind { return r.k }

// Of is the handle of a kind whose observations carry attributes A. Its zero
// value is not usable; the handles are the variables in table.go.
type Of[A any] struct{ ref }

// Obs is an observation of the kind.
func (k Of[A]) Obs(key string, a A) store.Obs {
	return store.Obs{Kind: k.k.Name, Key: key, Attrs: encode(a)}
}

// Attrs decodes a record's merged attributes, as encoding/json would from the
// stored JSON. A stored value that does not fit its field (a record written
// before the field's type changed) decodes as the field's zero value.
func (k Of[A]) Attrs(r store.Record) A {
	var a A
	if len(r.Attrs) > 0 {
		decode(r.Attrs, &a)
	}
	return a
}

// Keyed is the handle of a kind whose key is made from its attributes. An
// observation is made from the attributes alone, so its key always agrees with
// them, and Attrs rebuilds from a record's key the attributes the key carries.
type Keyed[A any] struct {
	Of[A]
	key func(A) string
	// rebuild fills in the empty fields of *a that key carries.
	rebuild func(key string, a *A)
}

// Key is the key of a record with attributes a. Only the fields the key
// carries need be set.
func (k Keyed[A]) Key(a A) string { return k.key(a) }

// Obs is the observation of a record with attributes a, under its Key.
func (k Keyed[A]) Obs(a A) store.Obs { return k.Of.Obs(k.key(a), a) }

// Attrs decodes a record's merged attributes as Of.Attrs does, and takes a
// field the record lacks and its key carries from the key: the store keeps
// attributes only from current observations, so a record that is no longer
// current has only its key.
func (k Keyed[A]) Attrs(r store.Record) A {
	a := k.Of.Attrs(r)
	k.rebuild(r.Key, &a)
	return a
}

// Bare is the handle of a kind whose observations carry no attributes.
type Bare struct{ ref }

// Obs is an observation of the kind.
func (k Bare) Obs(key string) store.Obs { return store.Obs{Kind: k.k.Name, Key: key} }

// encode turns attributes into the map the store keeps, in the form the store
// returns them (numbers as float64, lists as []any).
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

// defineKeyed defines a kind whose key is key(attributes), and whose
// attributes rebuild fills in from a key, setting only the empty fields.
func defineKeyed[A any](k Kind, key func(A) string, rebuild func(key string, a *A)) Keyed[A] {
	table = append(table, k)
	return Keyed[A]{Of: Of[A]{ref{k}}, key: key, rebuild: rebuild}
}

// defineJoined defines a kind whose key is the fields that fields selects,
// joined with "|" in that order, and rebuilt from a key with fillFromKey.
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

// fillFromKey sets each empty *dst to its part of a "|"-joined key, the last
// taking the rest of the key (a TXT value may hold a bar). It sets nothing
// when the key has too few parts, or when no *dst is empty.
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

// handle is a kind handle found by name. It reads; it cannot make observations.
type handle struct{ ref }

// Lookup returns the handle of a kind by name, for a reader that walks kinds by
// name (see All) and asks the Visibility about them.
func Lookup(name string) (Named, bool) {
	k, ok := Get(name)
	return handle{ref{k}}, ok
}

// All returns every kind sorted by name.
func All() []Kind { return slices.Clone(table) }

// Size is a byte count, or "<n>+" when the body was cut short and its real
// size is unknown. An exact size is stored as a number.
type Size string

// SizeOf is an exact size.
func SizeOf(n int64) Size { return Size(strconv.FormatInt(n, 10)) }

func (s Size) MarshalJSON() ([]byte, error) {
	// Only a canonical integer is a valid JSON number ("+5" and "007" parse but are not).
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
