package threatdata

import (
	"fmt"
	"time"
)

// Downloaded lists pass these rules after format validation. Runtime updates and built-in
// refreshes share them; reviewed maintainer refreshes may bypass CheckShrink. Spamhaus uses its
// timestamp, while ipapi.is dates are midnight UTC.

// CheckEmpty refuses a list with no entries.
func CheckEmpty(list string, entries int) error {
	if entries < 1 {
		return fmt.Errorf("%s: the list has no entries", list)
	}
	return nil
}

// CheckShrink rejects lists with fewer than half the active copy's entries. The error includes
// both counts and suggests a newer nyx build.
func CheckShrink(list string, entries, inUse int) error {
	if entries*2 < inUse {
		return fmt.Errorf("%s: %d entries is fewer than half the %d of the copy in use, so the list has probably changed shape; a newer build of nyx is the remedy",
			list, entries, inUse)
	}
	return nil
}

// CheckDate accepts dates through tomorrow UTC and rejects the following midnight or later.
func CheckDate(list string, date, now time.Time) error {
	utc := now.UTC()
	limit := time.Date(utc.Year(), utc.Month(), utc.Day()+2, 0, 0, 0, 0, time.UTC)
	if !date.Before(limit) {
		return fmt.Errorf("%s: dated %s, which is after the end of tomorrow (UTC)", list, date.UTC().Format(time.RFC3339))
	}
	return nil
}

// Newer requires a strictly later date than the active copy.
func Newer(date, inUse time.Time) bool { return date.After(inUse) }
