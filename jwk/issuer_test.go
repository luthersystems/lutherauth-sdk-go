// Copyright © 2026 The lutherauth authors

package jwk

import (
	"strings"
	"sync/atomic"
	"testing"
	"time"

	jwtgo "github.com/golang-jwt/jwt/v4"
	"github.com/mendsley/gojwk"
	"github.com/stretchr/testify/require"
)

// issuerTestSetup returns a minting helper for one key, and settings that
// serve that key for every issuer, the way a relying party that trusts one
// lutherauth JWKS is set up. fetches counts key lookups.
func issuerTestSetup(t *testing.T, opts ...Option) (*Settings, func(iss string) string, *atomic.Int32) {
	t.Helper()
	key := MakeTestKey()
	var fetches atomic.Int32
	serve := WithRetrieveWebKeysFn(func(string) (*gojwk.Key, error) {
		fetches.Add(1)
		k, err := gojwk.PublicKey(key.PubKey)
		if err != nil {
			return nil, err
		}
		k.Kid = key.Kid
		return k, nil
	})
	mint := func(iss string) string {
		claims := &TestClaims{}
		claims.Issuer = iss
		claims.Subject = "alice"
		claims.ExpiresAt = jwtgo.NewNumericDate(time.Now().Add(time.Hour))
		tok, err := NewJWK(key.PrvKey, claims, key.Kid)
		require.NoError(t, err)
		return tok
	}
	return NewSettings(append([]Option{serve}, opts...)...), mint, &fetches
}

// TestRefreshIssuerRejected pins #51: a lutherauth refresh token (issuer
// ending "_refresh") is never accepted as a bearer token, even with no
// issuer allowlist. lutherauth signed refresh tokens with the access token
// key before luthersystems/lutherauth#101, and such tokens live for days.
func TestRefreshIssuerRejected(t *testing.T) {
	t.Parallel()
	settings, mint, fetches := issuerTestSetup(t)

	_, err := ValidateRS256(settings, &TestClaims{}, mint("luther:auth:_refresh"))
	require.ErrorIs(t, err, ErrRefreshToken)
	require.Zero(t, fetches.Load(), "refresh token caused a key fetch")

	_, err = ValidateRS256(settings, &TestClaims{}, mint("luther:auth:"))
	require.NoError(t, err)
}

// TestWithExpectedIssuers pins #51: with an allowlist, another issuer is
// refused before any key fetch, even when the same key signed it.
func TestWithExpectedIssuers(t *testing.T) {
	t.Parallel()
	settings, mint, fetches := issuerTestSetup(t, WithExpectedIssuers("luther:auth:"))

	_, err := ValidateRS256(settings, &TestClaims{}, mint("someone:else"))
	require.ErrorIs(t, err, ErrIssuerNotAccepted)
	require.Zero(t, fetches.Load())

	_, err = ValidateRS256(settings, &TestClaims{}, mint("luther:auth:"))
	require.NoError(t, err)
}

// TestWithExpectedIssuersAccumulates checks that several calls union their
// lists, like the other With* options.
func TestWithExpectedIssuersAccumulates(t *testing.T) {
	t.Parallel()
	settings, mint, _ := issuerTestSetup(t, WithExpectedIssuers("a"), WithExpectedIssuers("b"))
	for _, iss := range []string{"a", "b"} {
		_, err := ValidateRS256(settings, &TestClaims{}, mint(iss))
		require.NoError(t, err, iss)
	}
	_, err := ValidateRS256(settings, &TestClaims{}, mint("c"))
	require.ErrorIs(t, err, ErrIssuerNotAccepted)
}

// TestValidateErrorOmitsToken pins #51: a failed signature check must not
// put the bearer token into the error, which callers log.
func TestValidateErrorOmitsToken(t *testing.T) {
	t.Parallel()
	settings, _, _ := issuerTestSetup(t)
	other := MakeTestKey()
	claims := &TestClaims{}
	claims.Issuer = "luther:auth:"
	claims.ExpiresAt = jwtgo.NewNumericDate(time.Now().Add(time.Hour))
	// Signed by another key with the served kid: the signature check fails.
	tok, err := NewJWK(other.PrvKey, claims, kidOf(t, settings))
	require.NoError(t, err)
	_, err = ValidateRS256(settings, &TestClaims{}, tok)
	require.Error(t, err)
	require.NotContains(t, err.Error(), tok, "error text contains the token")
	sig := tok[strings.LastIndex(tok, ".")+1:]
	require.NotContains(t, err.Error(), sig, "error text contains the signature")
}

func kidOf(t *testing.T, s *Settings) string {
	t.Helper()
	k, err := s.retrieveWebKeys("x")
	require.NoError(t, err)
	return k.Kid
}

// TestWithExpectedIssuersEmptyFailsClosed checks that a pin whose list came
// out empty (an unset setting) accepts nothing, rather than every issuer.
func TestWithExpectedIssuersEmptyFailsClosed(t *testing.T) {
	t.Parallel()
	var unset []string
	settings, mint, _ := issuerTestSetup(t, WithExpectedIssuers(unset...))
	_, err := ValidateRS256(settings, &TestClaims{}, mint("luther:auth:"))
	require.ErrorIs(t, err, ErrIssuerNotAccepted)
}

// TestWithAllowRefreshIssuers checks the opt-out for an IdP that is not
// lutherauth and whose issuer happens to end in _refresh.
func TestWithAllowRefreshIssuers(t *testing.T) {
	t.Parallel()
	settings, mint, _ := issuerTestSetup(t, WithAllowRefreshIssuers())
	_, err := ValidateRS256(settings, &TestClaims{}, mint("https://idp.example/acme_refresh"))
	require.NoError(t, err)
}

// TestIssuerErrorIsCapped checks that a long unverified issuer is cut in
// the error, which callers log.
func TestIssuerErrorIsCapped(t *testing.T) {
	t.Parallel()
	settings, mint, _ := issuerTestSetup(t, WithExpectedIssuers("luther:auth:"))
	long := strings.Repeat("x", 5000)
	_, err := ValidateRS256(settings, &TestClaims{}, mint(long))
	require.ErrorIs(t, err, ErrIssuerNotAccepted)
	require.Less(t, len(err.Error()), 200)
}
