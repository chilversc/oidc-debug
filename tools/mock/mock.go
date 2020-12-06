package main

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/go-openapi/runtime"
	httptransport "github.com/go-openapi/runtime/client"
	hydra "github.com/ory/hydra-client-go/client"
	"github.com/ory/hydra-client-go/client/admin"
	"github.com/ory/hydra-client-go/models"
	"github.com/withmandala/go-log"
)

var client *hydra.OryHydra
var logger = log.New(os.Stderr)

func main() {
	host := "localhost:4446"
	hydraURL, err := url.Parse("http://localhost:4445/")
	if err != nil {
		fmt.Printf("Error parsing URL: %v", err)
	}

	transport := transport(hydraURL)
	client = hydra.New(transport, nil)

	http.HandleFunc("/login", handleLogin)
	http.HandleFunc("/consent", handleConsent)

	logger.Infof("Starting HTTP server on %s to handle hydra authentication requests", host)
	err = http.ListenAndServe(host, nil)

	if err != nil {
		logger.Fatalf("failed to start http server: %v", err)
		os.Exit(1)
	}
}

func transport(hydraURL *url.URL) runtime.ClientTransport {
	dialer := &net.Dialer{
		Timeout:   30 * time.Second,
		KeepAlive: 30 * time.Second,
		DualStack: true,
	}

	transport := &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		DialContext:           dialer.DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
	}

	client := &http.Client{
		Transport: transport,
	}

	return httptransport.NewWithClient(
		hydraURL.Host,
		hydraURL.Path,
		[]string{hydraURL.Scheme},
		client)
}

func handleLogin(w http.ResponseWriter, r *http.Request) {
	logger.Infof("received %s %s\n", r.Method, r.URL.Path)

	challenge := r.URL.Query().Get("login_challenge")
	if challenge == "" {
		logger.Error("request from hydra missing challenge")
		http.Error(w, "request from hydra missing challenge", http.StatusBadRequest)
		return
	}

	subject := "user@test"
	result, err := client.Admin.AcceptLoginRequest(admin.
		NewAcceptLoginRequestParams().
		WithLoginChallenge(challenge).
		WithBody(&models.AcceptLoginRequest{
			Subject: &subject,
		}))

	if err != nil {
		logger.Errorf("hydra AcceptLoginRequest failed: %v", err)
		http.Error(w, fmt.Sprintf("hydra AcceptLoginRequest failed: %v", err), http.StatusInternalServerError)
		return
	}

	redirect := result.Payload.RedirectTo
	if redirect == nil {
		logger.Errorf("hydra response missing redirect")
		http.Error(w, "hydra response missing redirect", http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, *redirect, http.StatusFound)
}

func handleConsent(w http.ResponseWriter, r *http.Request) {
	logger.Infof("received %s %s\n", r.Method, r.URL.Path)

	challenge := r.URL.Query().Get("consent_challenge")
	if challenge == "" {
		logger.Error("request from hydra missing challenge")
		http.Error(w, "request from hydra missing challenge", http.StatusBadRequest)
		return
	}

	r1, err := client.Admin.GetConsentRequest(admin.NewGetConsentRequestParams().WithConsentChallenge(challenge))
	if err != nil {
		logger.Errorf("hydra GetConsentRequest failed: %v", err)
		http.Error(w, fmt.Sprintf("hydra GetConsentRequest failed: %v", err), http.StatusInternalServerError)
		return
	}

	r2, err := client.Admin.AcceptConsentRequest(admin.
		NewAcceptConsentRequestParams().
		WithConsentChallenge(challenge).
		WithBody(&models.AcceptConsentRequest{
			GrantAccessTokenAudience: r1.Payload.RequestedAccessTokenAudience,
			GrantScope:               r1.Payload.RequestedScope,
			Session: &models.ConsentRequestSession{
				IDToken: map[string]interface{}{
					"group": []string{"developers@test", "users@test"},
				},
			},
		}))

	if err != nil {
		logger.Errorf("hydra AcceptConsentRequest failed: %v", err)
		http.Error(w, fmt.Sprintf("hydra AcceptConsentRequest failed: %v", err), http.StatusInternalServerError)
		return
	}

	redirect := r2.Payload.RedirectTo
	if redirect == nil {
		logger.Error("hydra response missing redirect")
		http.Error(w, "hydra response missing redirect", http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, *redirect, http.StatusFound)
}
