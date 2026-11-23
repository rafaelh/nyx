package threatdata

import (
	"fmt"
	"time"
)

// The acceptance rules a downloaded list must pass, beside its own format (spamhaus.ParseDrop and
// ParseASNDrop, abusive.ParseNetworksPage and ParseASNsPage). An update applies all of them; the
// maintainer's refresh of the built-in copies applies the same ones, except that a maintainer who
// has reviewed a shrunken list may skip CheckShrink. A list's date is its Spamhaus timestamp, or
// its ipapi.is day at 00:00 UTC.

// CheckEmpty refuses a list with no entries.
func CheckEmpty(list string, entries int) error {
	if entries < 1 {
		return fmt.Errorf("%s: the list has no entries", list)
	}
	return nil
}

// CheckShrink refuses a list holding fewer than half the entries of the copy in use. Its error
// names the rule and both counts, and says that a newer build of nyx is the remedy.
func CheckShrink(list string, entries, inUse int) error {
	if entries*2 < inUse {
		return fmt.Errorf("%s: %d entries is fewer than half the %d of the copy in use, so the list has probably changed shape; a newer build of nyx is the remedy",
			list, entries, inUse)
	}
	return nil
}

// CheckDate refuses a list dated after the end of tomorrow, UTC: at or after 00:00 UTC two days
// after now.
func CheckDate(list string, date, now time.Time) error {
	utc := now.UTC()
	limit := time.Date(utc.Year(), utc.Month(), utc.Day()+2, 0, 0, 0, 0, time.UTC)
	if !date.Before(limit) {
		return fmt.Errorf("%s: dated %s, which is after the end of tomorrow (UTC)", list, date.UTC().Format(time.RFC3339))
	}
	return nil
}

// Newer reports whether a list dated date replaces the copy in use, dated inUse. A list dated no
// later is already current.
func Newer(date, inUse time.Time) bool { return date.After(inUse) }
