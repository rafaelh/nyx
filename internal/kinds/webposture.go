package kinds

// WebPosture holds HSTS, cookie, directory-listing and version-disclosure evidence for
// low-severity findings. The probe writes it with the same-key web_service record. A separate
// kind keeps posture fields out of WebServiceAttrs.
var WebPosture = define[WebPostureAttrs](Kind{Name: "web_posture", HostAttr: "host"})

// WebPostureAttrs records host and response evidence. HSTS applies only to HTTPS. Cookie fields
// contain sorted, semicolon-separated names, never values; Secure is checked only over HTTPS.
// VersionDisclosure joins versioned Server and X-Powered-By values with semicolons.
type WebPostureAttrs struct {
	Host              string `json:"host"`
	HSTS              *bool  `json:"hsts,omitempty"`
	CookiesNoSecure   string `json:"cookies_no_secure,omitempty"`
	CookiesNoHTTPOnly string `json:"cookies_no_httponly,omitempty"`
	DirectoryListing  bool   `json:"directory_listing"`
	VersionDisclosure string `json:"version_disclosure,omitempty"`
}
