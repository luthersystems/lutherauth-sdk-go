// Copyright © 2026 The lutherauth authors

package jwk

import (
	"testing"

	jwtgo "github.com/golang-jwt/jwt/v4"
)

// Issuers used by the audience/subject tests. vercelISS models a Vercel OIDC
// workload issuer (luthersystems/reliable#2175); legacyISS models the existing
// lutherauth issuer that must remain unchecked for audience/subject.
const (
	vercelISS = "https://oidc.vercel.com/luther"
	legacyISS = "luther:auth:ui-prod"

	vercelAud = "https://vercel.com/luther"
	vercelSub = "owner:luther:project:reliable:environment:production"
)

// audienceTestKeys builds JWKS for both issuers and a minting helper that signs
// a token for an issuer with a given subject and audience set.
func audienceTestKeys(t *testing.T) (Option, func(iss, sub string, aud ...string) string) {
	t.Helper()
	keysByIssuer := map[string]*issuerKeys{
		vercelISS: makeIssuerJWKS(2),
		legacyISS: makeIssuerJWKS(2),
	}
	serve := allIssuerOption(keysByIssuer, 0)
	mint := func(iss, sub string, aud ...string) string {
		claims := &TestClaims{}
		claims.Issuer = iss
		claims.Subject = sub
		claims.Audience = jwtgo.ClaimStrings(aud)
		ik := keysByIssuer[iss]
		kid := randomKID(ik.pubKeys)
		token, err := NewJWK(ik.prvKeys[kid], claims, kid)
		if err != nil {
			t.Fatalf("mint token: %s", err)
		}
		return token
	}
	return serve, mint
}

// TestWithExpectedAudienceAndSubject verifies per-issuer audience + subject
// pinning: the Vercel issuer is constrained while the legacy issuer is left
// unchecked (backwards-compatible).
func TestWithExpectedAudienceAndSubject(t *testing.T) {
	t.Parallel()

	serve, mint := audienceTestKeys(t)
	settings := NewSettings(
		serve,
		WithExpectedAudience(func(issuer string) []string {
			if issuer == vercelISS {
				return []string{vercelAud}
			}
			return nil // legacy issuer: audience not checked
		}),
		WithExpectedSubject(func(issuer string) []string {
			if issuer == vercelISS {
				return []string{vercelSub}
			}
			return nil // legacy issuer: subject not checked
		}),
	)

	tests := []struct {
		name    string
		token   string
		wantErr bool
	}{
		{
			name:  "vercel matching aud+sub accepted",
			token: mint(vercelISS, vercelSub, vercelAud),
		},
		{
			name:  "vercel multi-aud containing expected accepted",
			token: mint(vercelISS, vercelSub, "https://sts.amazonaws.com", vercelAud),
		},
		{
			name:    "vercel wrong audience rejected",
			token:   mint(vercelISS, vercelSub, "https://sts.amazonaws.com"),
			wantErr: true,
		},
		{
			name:    "vercel preview-environment subject rejected",
			token:   mint(vercelISS, "owner:luther:project:reliable:environment:preview", vercelAud),
			wantErr: true,
		},
		{
			name:    "vercel missing audience rejected",
			token:   mint(vercelISS, vercelSub),
			wantErr: true,
		},
		{
			name:  "legacy issuer aud+sub unchecked (backwards compatible)",
			token: mint(legacyISS, "anything", "anything"),
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := ValidateRS256(settings, &TestClaims{}, tc.token)
			if tc.wantErr && err == nil {
				t.Fatalf("expected error, got nil")
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("unexpected error: %s", err)
			}
		})
	}
}

// TestExpectedAudienceEmptyMeansUnchecked confirms that a configured function
// returning an empty set leaves the audience unchecked (only a non-empty set
// pins it), so enabling the option for one issuer never tightens another.
func TestExpectedAudienceEmptyMeansUnchecked(t *testing.T) {
	t.Parallel()

	serve, mint := audienceTestKeys(t)
	settings := NewSettings(
		serve,
		WithExpectedAudience(func(string) []string { return []string{} }),
		WithExpectedSubject(func(string) []string { return nil }),
	)

	// Any audience is fine because the expected set is empty.
	if _, err := ValidateRS256(settings, &TestClaims{}, mint(vercelISS, "whoever", "any-aud")); err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
}

// TestExpectedAudienceUnionsAcrossOptions confirms multiple WithExpectedAudience
// options accumulate (union) for the same issuer.
func TestExpectedAudienceUnionsAcrossOptions(t *testing.T) {
	t.Parallel()

	serve, mint := audienceTestKeys(t)
	settings := NewSettings(
		serve,
		WithExpectedAudience(func(string) []string { return []string{"aud-a"} }),
		WithExpectedAudience(func(string) []string { return []string{"aud-b"} }),
	)

	for _, aud := range []string{"aud-a", "aud-b"} {
		if _, err := ValidateRS256(settings, &TestClaims{}, mint(vercelISS, "s", aud)); err != nil {
			t.Fatalf("aud %q should be accepted via union: %s", aud, err)
		}
	}
	if _, err := ValidateRS256(settings, &TestClaims{}, mint(vercelISS, "s", "aud-c")); err == nil {
		t.Fatalf("aud-c should be rejected (not in union)")
	}
}
