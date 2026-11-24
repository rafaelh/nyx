// Package banner extracts recognised SSH, FTP and SMTP products/versions and detects
// distribution builds without I/O.
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

// number limits captured versions to letters, digits and dots so banner control characters
// cannot enter version output.
const number = `([0-9][0-9A-Za-z.]*)`

// word requires a product/version boundary that excludes hostname fragments, so
// "postfix.example.com" is not mistaken for the mail server product.
const word = `(?:[^.\w\n]|$)`

// First matching rule wins. SSH banners anchor at line start; other protocols allow prefixes.
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

// distro recognises distribution names and package revision suffixes such as +deb12u3 or .el7.
var distro = regexp.MustCompile(`(?i)debian|ubuntu|centos|red ?hat|rhel|fedora|suse|alpine|amazon linux|rocky|almalinux|raspbian|\+deb\d|~deb\d|~bpo|\+dfsg|[-.]el\d|\.fc\d`)

// Distro detects distribution version suffixes. These builds may contain backported fixes, so
// upstream version age alone does not establish missing support.
func Distro(version string) bool { return distro.MatchString(version) }

// Parse extracts a recognised product/version and distribution-build flag. Decode stored
// banners first with kinds.DecodeBanner. Unknown banners return empty values; missing versions
// remain empty. Captured versions contain only letters, digits and dots.
func Parse(text string) (product, version string, isDistro bool) {
	for _, r := range rules {
		loc := r.re.FindStringSubmatchIndex(text)
		if loc == nil {
			continue
		}
		if len(loc) > 3 && loc[2] >= 0 {
			version = text[loc[2]:loc[3]]
		}
		// Inspect same-line suffixes such as (Debian) or Ubuntu package revisions.
		rest, _, _ := strings.Cut(text[loc[1]:], "\n")
		return r.product, version, Distro(rest)
	}
	return "", "", false
}
