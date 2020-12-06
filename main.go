package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/coreos/go-oidc"
	"github.com/pkg/browser"
	"golang.org/x/oauth2"
)

type Config struct {
	IssuerURL string
	Insecure  bool

	ClientID     string
	ClientSecret string
	ClientPort   int
}

func main() {
	cfg := Config{
		IssuerURL: "http://localhost:4444/",
	}

	if cfg.ClientPort < 1 {
		cfg.ClientPort = 4447
	}
	clientURL := url.URL{
		Scheme: "http",
		Host:   fmt.Sprintf("localhost:%d", cfg.ClientPort),
		Path:   "/",
	}

	client := client(cfg)
	ctx := oidc.ClientContext(context.Background(), client)
	provider, err := oidc.NewProvider(ctx, cfg.IssuerURL)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	showProvider(provider)

	// Configure an OpenID Connect aware OAuth2 client.
	oauth2Config := &oauth2.Config{
		ClientID:     "test",
		ClientSecret: "123456",
		RedirectURL:  clientURL.ResolveReference(&url.URL{Path: "callback"}).String(),

		// Discovery returns the OAuth2 endpoints.
		Endpoint: provider.Endpoint(),

		// "openid" is a required scope for OpenID Connect flows.
		Scopes: []string{oidc.ScopeOpenID},
	}

	done := make(chan error, 1)

	http.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		fmt.Printf("Received %s %s\n", r.Method, r.URL.Path)

		switch r.Method {
		case http.MethodHead:
		case http.MethodGet:
			authURL := oauth2Config.AuthCodeURL("no-csrf-here", oauth2.AccessTypeOnline)
			fmt.Printf("Redirecting client to %s\n", authURL)
			http.Redirect(w, r, authURL, http.StatusFound)

		default:
			http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		}
	})

	http.HandleFunc("/callback", func(w http.ResponseWriter, r *http.Request) {
		fmt.Printf("Received %s %s\n", r.Method, r.URL.Path)

		switch r.Method {
		case http.MethodHead:
		case http.MethodGet:
			q := r.URL.Query()

			code := q.Get("code")
			if code != "" {
				showCode(ctx, oauth2Config, code)
			}

			idToken := q.Get("id_token")
			if idToken != "" {
				showToken(idToken)
			}

			token := q.Get("token")
			if token != "" {
				showToken(token)
			}

			w.WriteHeader(http.StatusOK)
			w.Write([]byte("done"))

			close(done)
			done = nil

		default:
			http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		}
	})

	go func() {
		err := http.ListenAndServe(clientURL.Host, nil)
		if err != nil && done != nil {
			done <- err
		}
		close(done)
	}()

	err = browser.OpenURL(clientURL.ResolveReference(&url.URL{Path: "login"}).String())
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	err = <-done
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func client(cfg Config) *http.Client {
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
			InsecureSkipVerify: cfg.Insecure,
		},
	}

	return &http.Client{
		Transport: transport,
	}
}

func showProvider(provider *oidc.Provider) {
	endpoint := provider.Endpoint()

	fmt.Println("Resolved provider endpoint")
	fmt.Printf("  AuthURL:   %s\n", endpoint.AuthURL)
	fmt.Printf("  TokenURL:  %s\n", endpoint.TokenURL)

	claims, err := fetchClaimsAsJSON(provider)
	if err != nil {
		fmt.Printf("Error getting claims from provider: %v", err)
	} else {
		fmt.Println("Claims supported by provider")
		fmt.Println(claims)
	}
}

func fetchClaimsAsJSON(provider *oidc.Provider) (string, error) {
	var data json.RawMessage
	err := provider.Claims(&data)
	if err != nil {
		return "", err
	}

	return pp(data, "  ")
}

func showCode(ctx context.Context, oauth2Config *oauth2.Config, code string) {
	fmt.Println("Exchanging code for token")
	token, err := oauth2Config.Exchange(ctx, code)

	if err != nil {
		fmt.Printf("Error exchanging code for token: %v\n", err)
		return
	}

	raw := token.Extra("id_token")
	if raw == nil {
		fmt.Println("Result did not contain an id_token")
		return
	}

	str, ok := raw.(string)
	if !ok {
		fmt.Println("id_token was not of type string")
		return
	}

	if str == "" {
		fmt.Println("id_token was empty")
		return
	}

	showToken(str)
}

func showToken(str string) {
	decoded, err := decode(str)
	if err != nil {
		fmt.Printf("Failed to decode jwt: %v", err)
	}

	fmt.Println(decoded)
}

func decode(payload string) (string, error) {
	s := strings.Split(payload, ".")
	if len(s) < 2 {
		return "", errors.New("jws: invalid token received")
	}

	decoded, err := base64.RawURLEncoding.DecodeString(s[1])
	if err != nil {
		return "", err
	}

	return pp(decoded, "  ")
}

func pp(data []byte, prefix string) (string, error) {
	var buf bytes.Buffer

	// json.Indent does not include the prefix before the first line
	_, err := buf.WriteString(prefix)
	if err != nil {
		return "", err
	}

	err = json.Indent(&buf, data, prefix, "  ")
	if err != nil {
		return "", err
	}

	return buf.String(), nil
}
