// Package testmock provides a simple OIDC server that replies with pre-canned responses.
package testmock

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"time"

	"github.com/justinas/alice"
	"gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/jwt"
)

const testKey = "MIICdgIBADANBgkqhkiG9w0BAQEFAASCAmAwggJcAgEAAoGBAMFHqgKhS4nHlTE5P0IauictV+9TtSVgIiC+aWVDqc41hNE1b30Tk/rTNv7AR1gVGnF0YCnxQ4o59b5KQriJmXFmPs/P8exyLXxDDEEQ34aSwJOTxBKKg/0U2JRmAA8QwAxa3jBg7X7ijMRR3hqWmjnd/kt4nn0uC0QnRSY6t6SRAgMBAAECgYB9RCAYokcd3f+ArpSkGERr3cRvNTZjKeIUjLQsUGU+Y4tYOCSw0L6IwtmS1DWpDcxcmcs1g8t9S8FMej6x8WRDa4HpSDbriU7wK1Om2hIn1izm0fNT6QJBhD4hY6mhXatrAy7CRa9jEoDU0pxh2NpxFm7apoLURSVq8BkCqFY1UQJBAPlse9wWjgwKebmRP6HqUr6NRR472z1nblokAeMVpLzKekRrzPvuUa1PApzt9WazgUsVSlWBCu+rfSxBAFCRV3UCQQDGYDsMRXiLBQQsv75JlwSWMgjoVb13yEDw3eVqQLX40z4K42YxxlSn5RWZ23CDF1qTjKUhtTQLXOPJboiR2pEtAkEAz44+477BJbPx50G/OfXMNVVJlwcoQci4Q7qC930jQRcc96LdSSfgP9/nxL8f3v6xMNHesZhYiWijGRheMq0/oQJAKPtKV4+mhnnD0gbOpd9H+Etf4beMy8kX+Wqt8VRrA3uIbrFptFC3vnOqEb3usXZKpP7CQoNvvAU1nbBzEEaqBQJAJbsctoC7k0BUsLFASyXkJqplCDmzukvfd4wmbRHlivmLqbMORvLHccYZHqwfSjUQ5pGWPXM4sNx4O2WibBu+xQ=="

// Serve creates a simple authentication server that returns pre-canned responses
// to test the oauth flow
func Serve() *httptest.Server {
	mux := http.NewServeMux()

	get := alice.New(assertGet)
	post := alice.New(assertPost)

	handleToken := &tokenHandler{}

	mux.Handle("/.well-known/openid-configuration", get.ThenFunc(handleWellKnownMetadata))
	mux.Handle("/oauth2/auth", get.ThenFunc(handleAuth))
	mux.Handle("/oauth2/token", post.Then(handleToken))
	mux.HandleFunc("/", handleNotFound)

	server := httptest.NewServer(mux)
	handleToken.issuer = server.URL

	return server
}

// OpenURL mimics the standard client browser by following the redirects.
// This is designed to work with testmock.Serve and expects every request
// to return a redirect except the last request.
func OpenURL(url string) error {
	// http.Get will automatically follow up to 10 redirects
	// which is enough for the oauth dance.
	res, err := http.Get(url)
	if err != nil {
		return err
	}
	defer res.Body.Close()

	if res.StatusCode != 200 {
		buf := new(strings.Builder)
		io.Copy(buf, res.Body)
		return fmt.Errorf("server response %s : %s", res.Status, buf.String())
	}
	return nil
}

func handleNotFound(w http.ResponseWriter, r *http.Request) {
	url := r.URL.String()
	msg := fmt.Sprintf("URL [%s] not found for [%s]", url, r.Method)
	http.Error(w, msg, http.StatusNotFound)
}

func handleWellKnownMetadata(w http.ResponseWriter, r *http.Request) {
	scheme := "http"
	if r.TLS != nil {
		scheme = "http"
	}
	body := wellKnownMetadata(scheme, r.Host)
	writeJSONString(w, body)
}

func handleAuth(w http.ResponseWriter, r *http.Request) {
	// TODO: capture the query string for instrospection
	q := r.URL.Query()
	callback := q.Get("redirect_uri")
	if callback == "" {
		http.Error(w, "request missing redirect_uri parameter", http.StatusBadRequest)
		return
	}

	// no error checking here for simplicity
	// assume URL does not already contain a query string
	callback += "?code=token-please"

	http.Redirect(w, r, callback, http.StatusSeeOther)
}

type tokenResponse struct {
	TokenType    string   `json:"token_type,omitempty"`
	IDToken      string   `json:"id_token,omitempty"`
	AccessToken  string   `json:"access_token,omitempty"`
	RefreshToken string   `json:"refresh_token,omitempty"`
	Scope        []string `json:"scope,omitempty"`
	ExpiresIn    uint32   `json:"expires_in,omitempty"`
}

type tokenHandler struct {
	issuer string
}

func (h tokenHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// TODO: capture form values for introspection by tests
	// https://tools.ietf.org/html/rfc6749#section-4.1.3
	//	grant_type (should be authorization_code)
	//	code
	// 	redirect_uri
	//	client_id

	key, err := loadTestKey()
	if err != nil {
		http.Error(w, fmt.Sprintf("could not load signing key : %v", err), http.StatusInternalServerError)
		return
	}

	opt := new(jose.SignerOptions).WithType("JWT")
	sig, err := jose.NewSigner(key, opt)
	if err != nil {
		http.Error(w, fmt.Sprintf("could not create signer : %v", err), http.StatusInternalServerError)
		return
	}

	now := time.Now()
	claims := jwt.Claims{
		Issuer:    h.issuer,
		Audience:  jwt.Audience{"http://target.test/"},
		IssuedAt:  jwt.NewNumericDate(now),
		NotBefore: jwt.NewNumericDate(now.Add(5 * time.Minute)),
		Expiry:    jwt.NewNumericDate(now.Add(10 * time.Minute)),
		Subject:   "someone@test",
	}
	group := struct {
		Group []string `json:"group,omitempty"`
	}{
		Group: []string{
			"devs@test",
			"users@test",
		},
	}

	token, err := jwt.
		Signed(sig).
		Claims(claims).
		Claims(group).
		CompactSerialize()

	if err != nil {
		http.Error(w, fmt.Sprintf("could not sign jwt : %v", err), http.StatusInternalServerError)
		return
	}

	response := tokenResponse{
		TokenType:    "Bearer",
		IDToken:      token,
		AccessToken:  "let-me-in",
		RefreshToken: "another-token-please",
		Scope:        []string{"openid"},
		ExpiresIn:    uint32((5 * time.Minute) / time.Second),
	}

	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	writeJSON(w, response)
}

var (
	assertGet  = assertMethod(http.MethodGet)
	assertPost = assertMethod(http.MethodPost)
)

func assertMethod(method string) alice.Constructor {
	return alice.Constructor(func(next http.Handler) http.Handler {
		return assertMethodHandler(method, next)
	})
}

func assertMethodHandler(method string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// for simplicy of tests, ignoring HEAD
		if r.Method != method {
			http.Error(w, fmt.Sprintf("method [%s] not allowed for URL [%s]", r.Method, r.URL.String()), http.StatusMethodNotAllowed)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func writeJSON(w http.ResponseWriter, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	e := json.NewEncoder(w)
	e.SetIndent("", "  ")
	e.Encode(data)
}

func writeJSONString(w http.ResponseWriter, json string) {
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(json))
}

func loadTestKey() (jose.SigningKey, error) {
	der, err := base64.StdEncoding.DecodeString(testKey)
	if err != nil {
		return jose.SigningKey{}, err
	}

	key, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return jose.SigningKey{}, err
	}

	return jose.SigningKey{Algorithm: jose.PS256, Key: key}, nil
}
