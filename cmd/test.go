package cmd

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/coreos/go-oidc"
	"github.com/pkg/browser"
	"github.com/spf13/cobra"
	"golang.org/x/oauth2"
	"gopkg.in/yaml.v3"
)

type extra map[string]multivalue
type multivalue []string

type foo string

func (v multivalue) MarshalYAML() (interface{}, error) {
	if len(v) == 1 {
		return v[0], nil
	} else {
		return []string(v), nil
	}
}

func (v *multivalue) UnmarshalYAML(n *yaml.Node) error {
	if n.Kind == yaml.ScalarNode {
		// support single values in the format of
		// foo: "some value"
		var str string
		err := n.Decode(&str)
		if err != nil {
			return err
		}
		*v = multivalue{str}
		return nil
	}

	// otherwise defer back to the standard decoder, if the type is incompatble
	// this will produce a better error message than trying to do this ourselves
	return n.Decode((*[]string)(v))
}

type testConfig struct {
	IssuerURL string `yaml:"issuerURL"`
	Insecure  bool   `yaml:"insecure"`

	Scopes      []string `yaml:"scopes"`
	ExtraParams extra    `yaml:"extraParams"`

	ClientID     string `yaml:"clientID"`
	ClientSecret string `yaml:"clientSecret"`
	ClientPort   int    `yaml:"clientPort"`
}

func (cfg *testConfig) validate() error {
	err := make([]string, 0, 3)

	if cfg.IssuerURL == "" {
		err = append(err, "issuerURL is required")
	}

	if cfg.ClientID == "" {
		err = append(err, "clientID is required")
	}

	if cfg.ClientPort < 1 || cfg.ClientPort > math.MaxUint16 {
		err = append(err, fmt.Sprintf("clientPort [%d] is invalid", cfg.ClientPort))
	}

	if len(err) > 0 {
		return fmt.Errorf("config errors:\n  %s", strings.Join(err, "\n  "))
	}

	return nil
}

var testCmd = &cobra.Command{
	Use:   "test",
	Short: "Test JWT issued by OIDC server",
	Long:  `Handles a simple OIDC authentication flow and displays the JWT that was issued.`,
	Run:   test,
}

var testConfigFile string

func init() {
	f := testCmd.Flags()
	f.StringVarP(&testConfigFile, "config", "c", "", "")
	testCmd.MarkFlagRequired("config")
	rootCmd.AddCommand(testCmd)
}

func test(cmd *cobra.Command, args []string) {
	cfg, err := loadConfig(testConfigFile)
	if err != nil {
		fmt.Printf("Error reading config: %v\n", err)
		return
	}

	fmt.Println("The config is")
	str, err := yp(cfg, "  | ")
	if err != nil {
		fmt.Printf("  Error displaying config: %v", err)
		return
	}
	fmt.Println(str)

	err = cfg.validate()
	if err != nil {
		fmt.Println("Configuration errors:")
		fmt.Println(err)
		return
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

func loadConfig(path string) (testConfig, error) {
	cfg := testConfig{
		ClientPort: 4447,
	}

	f, err := os.Open(path)
	if err != nil {
		return cfg, err
	}
	defer f.Close()

	err = yaml.NewDecoder(f).Decode(&cfg)
	return cfg, err
}

func client(cfg testConfig) *http.Client {
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

func yp(in interface{}, prefix string) (string, error) {
	out, err := yaml.Marshal(in)
	if err != nil {
		return "", err
	}

	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	for i, l := range lines {
		lines[i] = prefix + l
	}

	return strings.Join(lines, "\n"), nil
}
