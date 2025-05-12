// Package gh has a minimal set of types for the subset of the Github API used
// by Hop Vend.
//
// The Github API for the user type is documented at
// https://docs.github.com/en/rest/users/users?apiVersion=2022-11-28#get-the-authenticated-user
//
// This package is based on the API version from 2022-11-28.
package gh

// User is a user object from the Github API /user endpoint.
type User struct {
	Login string `json:"login"`
	ID    int64  `json:"id"`
	Type  string `json:"type"`

	OrganizationsURL string `json:"organizations_url"`
}

// Organization is an organization object from the Github API
type Organization struct {
	Login string `json:"login"`
	ID    int64  `json:"id"`
	URL   string `json:"url"`
}
