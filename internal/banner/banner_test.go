package banner_test

import (
	"testing"

	"github.com/rafaelh/nyx/internal/banner"
)

// Parse reads the product and version a service names in its banner, and says whether the
// version is a distribution's build.
func TestParse(t *testing.T) {
	for _, tc := range []struct {
		name, banner, product, version string
		distro                         bool
	}{
		// SSH
		{"openssh", `SSH-2.0-OpenSSH_9.6`, "OpenSSH", "9.6", false},
		{"openssh with a portable patch level", `SSH-2.0-OpenSSH_8.2p1`, "OpenSSH", "8.2p1", false},
		{"openssh on ubuntu", `SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5`, "OpenSSH", "8.2p1", true},
		{"openssh on debian", "SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u3\r\n", "OpenSSH", "9.2p1", true},
		{"openssh with a version-suffixed protocol", `SSH-1.99-OpenSSH_4.3`, "OpenSSH", "4.3", false},
		{"dropbear", `SSH-2.0-dropbear_2020.81`, "Dropbear", "2020.81", false},
		{"dropbear without a version", `SSH-2.0-dropbear`, "Dropbear", "", false},
		{"another ssh server", `SSH-2.0-libssh_0.9.6`, "", "", false},
		// FTP
		{"proftpd", `220 ProFTPD 1.3.8 Server (ProFTPD Default Installation) [192.0.2.1]`, "ProFTPD", "1.3.8", false},
		{"proftpd with a letter", `220 ProFTPD 1.3.5e Server (Debian) [::ffff:192.0.2.1]`, "ProFTPD", "1.3.5e", true},
		{"proftpd without a version", `220 ProFTPD Server ready.`, "ProFTPD", "", false},
		{"vsftpd", `220 (vsFTPd 3.0.3)`, "vsftpd", "3.0.3", false},
		{"pure-ftpd", "220---------- Welcome to Pure-FTPd [privsep] [TLS] ----------\r\n220-You are user number 1", "Pure-FTPd", "", false},
		{"microsoft ftp", `220 Microsoft FTP Service`, "Microsoft IIS FTP", "", false},
		// SMTP
		{"postfix", `220 mail.example.com ESMTP Postfix`, "Postfix", "", false},
		{"postfix with a version", `220 mail.example.com ESMTP Postfix 3.4.13`, "Postfix", "3.4.13", false},
		{"postfix on ubuntu", `220 mail.example.com ESMTP Postfix (Ubuntu)`, "Postfix", "", true},
		{"exim", `220 mail.example.com ESMTP Exim 4.94.2 Tue, 17 Nov 2026 10:00:00 +0000`, "Exim", "4.94.2", false},
		{"sendmail", `220 mail.example.com ESMTP Sendmail 8.15.2/8.15.2; Tue, 17 Nov 2026 10:00:00 GMT`, "Sendmail", "8.15.2", false},
		{"sendmail on debian", `220 mail.example.com ESMTP Sendmail 8.15.2/8.15.2/Debian-22ubuntu3; Tue, 17 Nov 2026`, "Sendmail", "8.15.2", true},
		{"exchange", `220 EXCH01.example.com Microsoft ESMTP MAIL Service ready at Tue, 17 Nov 2026 10:00:00 +0000`, "Microsoft Exchange", "", false},
		{"exchange with a version", `220 EXCH01.example.com Microsoft ESMTP MAIL Service, Version: 8.3.348.2 ready at Tue`, "Microsoft Exchange", "8.3.348.2", false},
		// Neither
		{"an empty banner", ``, "", "", false},
		{"an http banner", `HTTP/1.1 400 Bad Request`, "", "", false},
		{"binary", "\x00\x00\x1e\xff", "", "", false},
		{"an unrecognised smtp server", `220 mail.example.com ESMTP ready`, "", "", false},
		{"a name that only contains one", `220 ftp.example.com notvsftpd-ish`, "", "", false},
		{"a hostname that names another server", `220 postfix.example.com ESMTP Exim 4.94.2 Tue, 17 Nov 2026`, "Exim", "4.94.2", false},
		{"an ftp hostname that names another server", `220 proftpd.example.com FTP server (vsFTPd 3.0.3)`, "vsftpd", "3.0.3", false},
		{"a version at the end of a line", "220 mail.example.com ESMTP Exim 4.94.2\r\n220 ubuntu", "Exim", "4.94.2", false},
	} {
		product, version, distro := banner.Parse(tc.banner)
		if product != tc.product || version != tc.version || distro != tc.distro {
			t.Errorf("%s: Parse(%q) = %q %q %v, want %q %q %v", tc.name, tc.banner, product, version, distro, tc.product, tc.version, tc.distro)
		}
	}
}

// The product and version go into files people read, so terminal-acting characters in
// the banner never reach them.
func TestParse_ValuesAreSanitised(t *testing.T) {
	product, version, _ := banner.Parse("SSH-2.0-OpenSSH_8.2p1\x1b[31m")
	for _, s := range []string{product, version} {
		for _, r := range s {
			if r < 0x20 || r == 0x7f {
				t.Errorf("Parse left a control character in %q", s)
			}
		}
	}
	if product != "OpenSSH" {
		t.Errorf("product = %q", product)
	}
}

// Distro reads a version string that is not from a banner (a Wappalyzer technology's) the
// same way Parse does.
func TestDistro(t *testing.T) {
	for v, want := range map[string]bool{
		"7.4.3":                   false,
		"2.4.41":                  false,
		"1.3.5e":                  false,
		"7.4.3-4ubuntu2.19":       true,
		"8.2p1 Ubuntu-4ubuntu0.5": true,
		"2.4.37 (CentOS)":         true,
		"9.2p1 Debian-2+deb12u3":  true,
		"1.18.0+deb11u1":          true,
		"2.4.38~bpo9+1":           true,
		"5.4.16-el7":              true,
		"1.0.2k-fips (Red Hat)":   true,
		"8.2.0-rc1":               false,
		"":                        false,
	} {
		if got := banner.Distro(v); got != want {
			t.Errorf("Distro(%q) = %v, want %v", v, got, want)
		}
	}
}
