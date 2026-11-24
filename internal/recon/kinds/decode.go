package kinds

import (
	"encoding/json"
	"reflect"
	"strconv"
	"strings"
	"sync"
)

// decode fills dst from stored attributes, including JSON-style float64 numbers and []any
// lists. Wrongly typed pointer values remain nil to preserve "unknown". Common structs use a
// cached direct decoder because records are read by the thousand on every pass; other types
// fall back to JSON.
func decode(attrs map[string]any, dst any) {
	v := reflect.ValueOf(dst).Elem()
	if p := planFor(v.Type()); p != nil {
		for _, f := range p {
			if x, ok := attrs[f.name]; ok && x != nil {
				f.set(v.Field(f.index), x)
			}
		}
		return
	}
	if b, err := json.Marshal(attrs); err == nil {
		_ = json.Unmarshal(b, dst) // a mismatched field is skipped, the rest decode
	}
}

type field struct {
	name  string
	index int
	set   func(reflect.Value, any)
}

var plans sync.Map // reflect.Type -> []field, or nil to decode through JSON

func planFor(t reflect.Type) []field {
	if p, ok := plans.Load(t); ok {
		return p.([]field)
	}
	p := buildPlan(t)
	plans.Store(t, p)
	return p
}

var sizeType = reflect.TypeFor[Size]()

// buildPlan selects directly decodable fields, returning nil for unsupported struct layouts.
func buildPlan(t reflect.Type) []field {
	if t.Kind() != reflect.Struct {
		return nil
	}
	var out []field
	for i := range t.NumField() {
		sf := t.Field(i)
		name, _, _ := strings.Cut(sf.Tag.Get("json"), ",")
		if !sf.IsExported() || name == "" || name == "-" {
			return nil
		}
		set := setter(sf.Type)
		if set == nil {
			return nil
		}
		out = append(out, field{name: name, index: i, set: set})
	}
	return out
}

func setter(t reflect.Type) func(reflect.Value, any) {
	switch {
	case t == sizeType: // a number or a string
		return func(v reflect.Value, x any) {
			switch n := x.(type) {
			case string:
				v.SetString(n)
			case float64:
				v.SetString(strconv.FormatFloat(n, 'f', -1, 64))
			}
		}
	case t.Kind() == reflect.String:
		return func(v reflect.Value, x any) {
			if s, ok := x.(string); ok {
				v.SetString(s)
			}
		}
	case t.Kind() == reflect.Int:
		return func(v reflect.Value, x any) {
			if n, ok := x.(float64); ok && n == float64(int64(n)) {
				v.SetInt(int64(n))
			}
		}
	case t.Kind() == reflect.Bool:
		return func(v reflect.Value, x any) {
			if b, ok := x.(bool); ok {
				v.SetBool(b)
			}
		}
	case t.Kind() == reflect.Pointer && t.Elem().Kind() == reflect.Bool:
		return func(v reflect.Value, x any) {
			if b, ok := x.(bool); ok {
				v.Set(reflect.ValueOf(&b))
			}
		}
	case t.Kind() == reflect.Slice && t.Elem().Kind() == reflect.String:
		return func(v reflect.Value, x any) {
			list, ok := x.([]any)
			if !ok {
				return
			}
			out := make([]string, 0, len(list))
			for _, e := range list {
				s, ok := e.(string)
				if !ok {
					return // json.Unmarshal would fail the whole field
				}
				out = append(out, s)
			}
			v.Set(reflect.ValueOf(out))
		}
	}
	return nil
}
