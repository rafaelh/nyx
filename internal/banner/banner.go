// Package banner reads the product and version a service names in its banner, for the SSH,
// FTP and SMTP servers nyx recognises, and whether a version string (from a banner or
// elsewhere) is a distribution's build. It does no I/O.
package banner

import (
	"regexp"
	"strings"
)

// rule recognises one server. Its pattern's first group, when it matches, is the version.
type rule struct {
	product string
	re      *regexp.Regexp
}

// number is a version: digits, letters and dots only. That is what keeps terminal-acting
// characters in the target's banner out of the version, and so out of the files and the console
// (as sanitize.Text does for other target text); a rule must not capture more than this.
const number = `([0-9][0-9A-Za-z.]*)`

// word ends a product name (or its version) that is anywhere in the line: it must not run on
// into a dot or a word, so the name in a hostname (220 postfix.example.com ESMTP Exim 4.94)
// is not taken for the server.
const word = `(?:[^.\w\n]|$)`

// rules are tried in order and the first match wins. SSH banners start the line; the others
// are anywhere in it.
var rules = []rule{
	{"OpenSSH", regexp.MustCompile(`(?m)^SSH-\d\.\d+-OpenSSH_` + number)},
	{"Dropbear", regexp.MustCompile(`(?mi)^SSH-\d\.\d+-dropbear(?:_` + number + `)?`)},
	{"ProFTPD", regexp.MustCompile(`(?mi)\bProFTPD(?:\s+` + number + `)?` + word)},
	{"vsftpd", regexp.MustCompile(`(?mi)\bvsFTPd(?:\s+` + number + `)?` + word)},
	{"Pure-FTPd", regexp.MustCompile(`(?mi)\bPure-FTPd` + word)},
	{"Microsoft IIS FTP", regexp.MustCompile(`(?i)\bMicrosoft FTP Service\b`)},
	{"Postfix", regexp.MustCompile(`(?mi)\bPostfix(?:\s+([0-9][0-9.]*))?` + word)},
	{"Exim", regexp.MustCompile(`(?m)\bExim(?:\s+([0-9][0-9.]*))?` + word)},
	{"Sendmail", regexp.MustCompile(`(?m)\bSendmail(?:\s+([0-9][0-9.]*))?` + word)},
	{"Microsoft Exchange", regexp.MustCompile(`Microsoft ESMTP MAIL Service(?:,\s*Version:\s*([0-9][0-9.]*))?`)},
}

// distro matches what a distribution adds to a version: its name, or the marks of its package
// revisions (+deb12u3, ~bpo9, .el7, +dfsg).
var distro = regexp.MustCompile(`(?i)debian|ubuntu|centos|red ?hat|rhel|fedora|suse|alpine|amazon linux|rocky|almalinux|raspbian|\+deb\d|~deb\d|~bpo|\+dfsg|[-.]el\d|\.fc\d`)

// Distro reports whether a version carries a distribution suffix, such as 8.2p1 Ubuntu-4ubuntu0.5,
// 7.4.3-4ubuntu2 or 1.18.0+deb11u1. A distribution build may carry fixes under its own version, so
// its version alone does not show that it is out of date.
func Distro(version string) bool { return distro.MatchString(version) }

// Parse returns the product and version a banner's text names (a stored banner is decoded
// with kinds.DecodeBanner first), and whether the version is a distribution's build. A banner
// it does not recognise gives empty values, and a recognised one that names no version gives
// an empty version. The version holds only digits, letters and dots (see number), so it is as
// safe to print as sanitised text.
func Parse(text string) (product, version string, isDistro bool) {
	for _, r := range rules {
		loc := r.re.FindStringSubmatchIndex(text)
		if loc == nil {
			continue
		}
		if len(loc) > 3 && loc[2] >= 0 {
			version = text[loc[2]:loc[3]]
		}
		// What the server adds after its name, on the same line: (Debian), Ubuntu-4ubuntu0.5.
		rest, _, _ := strings.Cut(text[loc[1]:], "\n")
		return r.product, version, Distro(rest)
	}
	return "", "", false
}
