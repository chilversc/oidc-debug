package testmock

import "fmt"

func wellKnownMetadata(scheme, host string) string {
	return fmt.Sprintf(`{
  "issuer": "%[1]s://%[2]s/",
  "authorization_endpoint": "%[1]s://%[2]s/oauth2/auth",
  "token_endpoint": "%[1]s://%[2]s/oauth2/token",
  "jwks_uri": "%[1]s://%[2]s/.well-known/jwks.json",
  "subject_types_supported": [
    "public"
  ],
  "response_types_supported": [
    "code",
    "code id_token",
    "id_token",
    "token id_token",
    "token",
    "token id_token code"
  ],
  "claims_supported": [
    "sub",
    "group"
  ],
  "grant_types_supported": [
    "authorization_code",
    "implicit",
    "client_credentials",
    "refresh_token"
  ],
  "response_modes_supported": [
    "query",
    "fragment"
  ],
  "userinfo_endpoint": "%[1]s://%[2]s/userinfo",
  "scopes_supported": [
    "offline_access",
    "offline",
    "openid"
  ],
  "token_endpoint_auth_methods_supported": [
    "client_secret_post",
    "client_secret_basic",
    "private_key_jwt",
    "none"
  ],
  "userinfo_signing_alg_values_supported": [
    "none",
    "RS256"
  ],
  "id_token_signing_alg_values_supported": [
    "RS256"
  ],
  "request_parameter_supported": true,
  "request_uri_parameter_supported": true,
  "require_request_uri_registration": true,
  "claims_parameter_supported": false,
  "revocation_endpoint": "%[1]s://%[2]s/oauth2/revoke",
  "backchannel_logout_supported": true,
  "backchannel_logout_session_supported": true,
  "frontchannel_logout_supported": true,
  "frontchannel_logout_session_supported": true,
  "end_session_endpoint": "%[1]s://%[2]s/oauth2/sessions/logout"
}`, scheme, host)
}
