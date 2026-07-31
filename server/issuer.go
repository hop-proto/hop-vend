package server

import (
	"time"

	"hop.computer/hop/certs"
	"hop.computer/hop/keys"
)

func issueLeafFor(
	parent *certs.Certificate,
	publicKey keys.DHPublicKey,
	name certs.Name,
	validity time.Duration,
	now time.Time,
) (*certs.Certificate, error) {
	// Certificates store whole Unix seconds. Backdating by one second avoids a
	// newly issued credential appearing to be from the future after encoding.
	issuedAt := now.UTC().Truncate(time.Second).Add(-time.Second)
	return certs.IssueLeafAt(parent, &certs.Identity{
		PublicKey: publicKey,
		Names:     []certs.Name{name},
	}, issuedAt, validity)
}
