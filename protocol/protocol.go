// Package protocol defines the messages exchanged by hop-vend and its client.
package protocol

import "time"

// Login tells the client where to authenticate and when the request expires.
type Login struct {
	LoginURL  string    `json:"login_url"`
	ExpiresAt time.Time `json:"expires_at"`
}

// Credential is the result of an enrollment request. Error is set instead of
// the certificate fields when enrollment fails.
type Credential struct {
	Certificate  string    `json:"certificate,omitempty"`
	Intermediate string    `json:"intermediate,omitempty"`
	Username     string    `json:"username,omitempty"`
	ExpiresAt    time.Time `json:"expires_at,omitempty"`
	Error        string    `json:"error,omitempty"`
}
