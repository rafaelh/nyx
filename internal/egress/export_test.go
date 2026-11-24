package egress

// Expose the private classifier to external-package tests.
var (
	ClassifyDial  = classifyDial
	UDPRoute      = udpRoute
	CertTrustWith = certTrust
)
