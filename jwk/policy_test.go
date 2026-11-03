// Copyright © 2026 The lutherauth authors

package jwk

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	jwtgo "github.com/golang-jwt/jwt/v4"
	"github.com/mendsley/gojwk"
	"github.com/stretchr/testify/require"
)

// policyMinter signs tokens with one key and serves that key as a JWKS.
type policyMinter struct {
	t   *testing.T
	key *Key
}

func (m policyMinter) mint(iss, aud, sub string) string {
	m.t.Helper()
	claims := &TestClaims{}
	claims.Issuer = iss
	claims.Subject = sub
	if aud != "" {
		claims.Audience = jwtgo.ClaimStrings{aud}
	}
	claims.ExpiresAt = jwtgo.NewNumericDate(time.Now().Add(time.Hour))
	tok, err := NewJWK(m.key.PrvKey, claims, m.key.Kid)
	require.NoError(m.t, err)
	return tok
}

// jwksServer serves the key at /jwks.json, the way lutherauth serves
// /v1/auth/.well-known/jwks.json.
func (m policyMinter) jwksServer() *httptest.Server {
	m.t.Helper()
	k, err := gojwk.PublicKey(m.key.PubKey)
	require.NoError(m.t, err)
	k.Kid = m.key.Kid
	body, err := gojwk.Marshal(k)
	require.NoError(m.t, err)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/jwks.json" {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write(body)
	}))
	m.t.Cleanup(srv.Close)
	return srv
}

// TestWithIssuerPolicy checks that one option pins the issuer, its JWKS,
// its audiences and its subjects together, and that each part refuses a
// token that breaks it.
func TestWithIssuerPolicy(t *testing.T) {
	t.Parallel()
	m := policyMinter{t: t, key: MakeTestKey()}
	srv := m.jwksServer()
	settings := NewSettings(WithIssuerPolicy(map[string]IssuerPolicy{
		"luther:auth:": {
			JWKSURL:  srv.URL + "/jwks.json",
			Audience: []string{"my-app"},
		},
		"https://idp.example": {
			JWKSURL: srv.URL + "/jwks.json",
			Subject: []string{"workload-1"},
		},
	}))

	tests := []struct {
		name    string
		token   string
		wantErr string
	}{
		{"lutherauth token with the audience", m.mint("luther:auth:", "my-app", "alice"), ""},
		{"lutherauth token, wrong audience", m.mint("luther:auth:", "other-app", "alice"), "audience not accepted"},
		{"lutherauth token, no audience", m.mint("luther:auth:", "", "alice"), "audience not accepted"},
		{"second issuer, pinned subject", m.mint("https://idp.example", "", "workload-1"), ""},
		{"second issuer, other subject", m.mint("https://idp.example", "", "workload-2"), "subject not accepted"},
		{"issuer not in the policy", m.mint("someone:else", "my-app", "alice"), ErrIssuerNotAccepted.Error()},
		{"refresh token", m.mint("luther:auth:_refresh", "my-app", "alice"), ErrRefreshToken.Error()},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ValidateRS256(settings, &TestClaims{}, tt.token)
			if tt.wantErr == "" {
				require.NoError(t, err)
				return
			}
			require.ErrorContains(t, err, tt.wantErr)
		})
	}
}

// TestWithIssuerPolicyEmptyFailsClosed checks that an empty policy accepts
// nothing, as an empty WithExpectedIssuers does: a policy whose config came
// out empty must not turn into no policy.
func TestWithIssuerPolicyEmptyFailsClosed(t *testing.T) {
	t.Parallel()
	m := policyMinter{t: t, key: MakeTestKey()}
	settings := NewSettings(
		WithHardcodedKey(m.key.PubKey, m.key.Kid),
		WithIssuerPolicy(nil),
	)
	_, err := ValidateRS256(settings, &TestClaims{}, m.mint("luther:auth:", "my-app", "alice"))
	require.ErrorIs(t, err, ErrIssuerNotAccepted)
}

// TestWithIssuerPolicyCopiesInput checks that a change to the caller's map
// or slices after the call does not change the policy.
func TestWithIssuerPolicyCopiesInput(t *testing.T) {
	t.Parallel()
	m := policyMinter{t: t, key: MakeTestKey()}
	aud := []string{"my-app"}
	policies := map[string]IssuerPolicy{"luther:auth:": {Audience: aud}}
	settings := NewSettings(
		WithHardcodedKey(m.key.PubKey, m.key.Kid),
		WithIssuerPolicy(policies),
	)
	aud[0] = "other-app"
	policies["someone:else"] = IssuerPolicy{}

	_, err := ValidateRS256(settings, &TestClaims{}, m.mint("luther:auth:", "my-app", "alice"))
	require.NoError(t, err)
	_, err = ValidateRS256(settings, &TestClaims{}, m.mint("someone:else", "my-app", "alice"))
	require.ErrorIs(t, err, ErrIssuerNotAccepted)
}

// TestWithIssuerPolicyKeepsOtherOptions checks that WithIssuerPolicy adds to
// the older options and does not replace them, so a caller can move one
// issuer at a time.
func TestWithIssuerPolicyKeepsOtherOptions(t *testing.T) {
	t.Parallel()
	m := policyMinter{t: t, key: MakeTestKey()}
	settings := NewSettings(
		WithHardcodedKey(m.key.PubKey, m.key.Kid),
		WithExpectedIssuers("https://idp.example"),
		WithExpectedSubject(func(iss string) []string {
			if iss == "https://idp.example" {
				return []string{"workload-1"}
			}
			return nil
		}),
		WithIssuerPolicy(map[string]IssuerPolicy{"luther:auth:": {Audience: []string{"my-app"}}}),
	)
	_, err := ValidateRS256(settings, &TestClaims{}, m.mint("luther:auth:", "my-app", "alice"))
	require.NoError(t, err)
	_, err = ValidateRS256(settings, &TestClaims{}, m.mint("https://idp.example", "", "workload-1"))
	require.NoError(t, err)
	_, err = ValidateRS256(settings, &TestClaims{}, m.mint("https://idp.example", "", "workload-2"))
	require.ErrorContains(t, err, "subject not accepted")
}

// TestWithIssuerPolicyJWKSWins checks that each issuer's keys come from its
// own JWKSURL, even next to a catch-all WithIssuerToWebKeyURL, in either
// option order. Otherwise a token that names the policy's issuer but is
// signed with the catch-all's key would pass (#51).
func TestWithIssuerPolicyJWKSWins(t *testing.T) {
	t.Parallel()
	luther := policyMinter{t: t, key: MakeTestKey()}
	idp := policyMinter{t: t, key: MakeTestKey()}
	lutherURL := luther.jwksServer().URL + "/jwks.json"
	idpURL := idp.jwksServer().URL + "/jwks.json"
	catchAll := WithIssuerToWebKeyURL(func(string) (string, error) { return lutherURL, nil })
	policy := WithIssuerPolicy(map[string]IssuerPolicy{
		"luther:auth:":        {},
		"https://idp.example": {JWKSURL: idpURL},
	})
	for name, opts := range map[string][]Option{
		"catch-all first": {catchAll, policy},
		"policy first":    {policy, catchAll},
	} {
		t.Run(name, func(t *testing.T) {
			settings := NewSettings(opts...)
			_, err := ValidateRS256(settings, &TestClaims{}, idp.mint("https://idp.example", "", "w"))
			require.NoError(t, err, "IdP token checked against the wrong JWKS")
			_, err = ValidateRS256(settings, &TestClaims{}, luther.mint("https://idp.example", "", "w"))
			require.Error(t, err, "lutherauth key accepted for the IdP issuer")
			_, err = ValidateRS256(settings, &TestClaims{}, luther.mint("luther:auth:", "", "alice"))
			require.NoError(t, err, "issuer without a JWKSURL lost the other key options")
		})
	}
}

// TestWithIssuerPolicyReplacesOlderAudience checks that a policy's audience
// is the whole accepted set for its issuer, so a policy can make an older,
// wider WithExpectedAudience stricter.
func TestWithIssuerPolicyReplacesOlderAudience(t *testing.T) {
	t.Parallel()
	m := policyMinter{t: t, key: MakeTestKey()}
	settings := NewSettings(
		WithHardcodedKey(m.key.PubKey, m.key.Kid),
		WithExpectedAudience(func(string) []string { return []string{"legacy-app"} }),
		WithIssuerPolicy(map[string]IssuerPolicy{"luther:auth:": {Audience: []string{"my-app"}}}),
	)
	_, err := ValidateRS256(settings, &TestClaims{}, m.mint("luther:auth:", "legacy-app", "alice"))
	require.ErrorContains(t, err, "audience not accepted")
	_, err = ValidateRS256(settings, &TestClaims{}, m.mint("luther:auth:", "my-app", "alice"))
	require.NoError(t, err)
}

// TestWithIssuerPolicyAccumulates checks that several calls add issuers.
func TestWithIssuerPolicyAccumulates(t *testing.T) {
	t.Parallel()
	m := policyMinter{t: t, key: MakeTestKey()}
	settings := NewSettings(
		WithHardcodedKey(m.key.PubKey, m.key.Kid),
		WithIssuerPolicy(map[string]IssuerPolicy{"a": {}}),
		WithIssuerPolicy(map[string]IssuerPolicy{"b": {}}),
	)
	for _, iss := range []string{"a", "b"} {
		_, err := ValidateRS256(settings, &TestClaims{}, m.mint(iss, "", "alice"))
		require.NoError(t, err, iss)
	}
}

// TestIssuerPolicyLookupIsSafe pins the answers to a review question on
// retrieveWebKeys: its policy lookup cannot panic, and it never sees an
// issuer the policy refuses. A read of a nil map gives the zero value, so
// settings without WithIssuerPolicy fall through to the older options. A
// pinned settings refuses an unknown issuer before any key fetch, so that
// issuer never reaches retrieveWebKeys or a JWKS server.
func TestIssuerPolicyLookupIsSafe(t *testing.T) {
	t.Parallel()

	// No policy: issuerPolicies is nil. The lookup must not panic, and the
	// older key option must still serve the token.
	settings, mint, fetches := issuerTestSetup(t)
	require.Nil(t, settings.issuerPolicies)
	require.NotPanics(t, func() {
		_, err := ValidateRS256(settings, &TestClaims{}, mint("luther:auth:"))
		require.NoError(t, err)
	})
	require.EqualValues(t, 1, fetches.Load())

	// Policy: an issuer not in it is refused with no key fetch, from the
	// policy URL or the older option.
	m := policyMinter{t: t, key: MakeTestKey()}
	srv := m.jwksServer()
	settings, mint, fetches = issuerTestSetup(t, WithIssuerPolicy(map[string]IssuerPolicy{
		"luther:auth:": {JWKSURL: srv.URL + "/jwks.json"},
	}))
	_, err := ValidateRS256(settings, &TestClaims{}, mint("someone:else"))
	require.ErrorIs(t, err, ErrIssuerNotAccepted)
	require.Zero(t, fetches.Load())
}
