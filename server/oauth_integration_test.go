package server

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"golang.org/x/oauth2"

	"hop.computer/vend/server/config"
)

// TestOAuthFlow exercises the login and callback handlers with a mocked
// GitHub OAuth and API server.
func TestOAuthFlow(t *testing.T) {
	// Mock GitHub server.
	ghMux := http.NewServeMux()
	var gh *httptest.Server

	ghMux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		// Token exchange endpoint.
		if err := r.ParseForm(); err != nil {
			t.Fatalf("failed to parse token request: %v", err)
		}
		if r.Form.Get("code") != "code" {
			t.Fatalf("unexpected code: %q", r.Form.Get("code"))
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"access_token":"tok"}`)
	})

	ghMux.HandleFunc("/user", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"login":"testuser","organizations_url":"%s/orgs"}`,
			gh.URL)
	})

	ghMux.HandleFunc("/orgs", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `[]`)
	})

	ghMux.HandleFunc("/orgs/testorg/members/testuser", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(204)
	})

	gh = httptest.NewServer(ghMux)
	defer gh.Close()

	cfg := &config.Config{
		GitHubClientID:      "id",
		GitHubClientSecret:  "secret",
		GitHubOrg:           "testorg",
		IntermediateCAPath:  "../intermediate.pem",
		IntermediateKeyPath: "../intermediate.key.pem",
		CertValiditySeconds: 3600,
	}

	srv := New(cfg)
	srv.oauthConfig.Endpoint = oauth2.Endpoint{
		AuthURL:  gh.URL + "/auth",
		TokenURL: gh.URL + "/token",
	}
	srv.apiBaseURL = gh.URL

	// Perform /login request.
	rr := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/login", nil)
	srv.handleLogin(rr, req)

	if rr.Code != http.StatusFound {
		t.Fatalf("/login status = %d, want %d", rr.Code, http.StatusFound)
	}

	loc := rr.Header().Get("Location")
	u, err := url.Parse(loc)
	if err != nil {
		t.Fatalf("bad redirect url: %v", err)
	}
	state := u.Query().Get("state")
	cookie := rr.Result().Cookies()[0].Value

	// Call /callback with the returned state and a fake code.
	rr2 := httptest.NewRecorder()
	cbReq := httptest.NewRequest("GET", "/callback?code=code&state="+state, nil)
	cbReq.AddCookie(&http.Cookie{Name: "state", Value: cookie})
	srv.handleCallback(rr2, cbReq)

	if rr2.Code != http.StatusOK {
		t.Fatalf("/callback status = %d, want %d", rr2.Code, http.StatusOK)
	}

	body := rr2.Body.String()
	if !strings.Contains(body, "gh access token tok") {
		t.Fatalf("unexpected body: %s", body)
	}
}
