// Copyright © 2022 The lutherauth authors

package claims

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestAPIKeyValidator(t *testing.T) {
	t.Parallel()
	// happy path
	validator := NewAPIKeyValidator(NewRawTokenGetter("X-API-Key", true), []string{"luther", "95thesis", "martin"})
	ctx := makeContext(map[string]string{
		"x-api-key": "95thesis",
	})
	err := validator.Validate(ctx)
	require.NoError(t, err)

	// test bad key
	ctx = makeContext(map[string]string{
		"x-api-key": "fnord",
	})
	err = validator.Validate(ctx)
	require.Error(t, err)
}
func TestAddPreValidator(t *testing.T) {
	t.Parallel()
	// happy path
	token := NewFakeAuthToken(martinClaims)
	noAuthClaimsGetter := NewFakeAuthClaims(NewRawTokenGetter("Authorization", true))
	apiKeyValidator := NewAPIKeyValidator(NewRawTokenGetter("X-API-Key", true), []string{"luther", "95thesis", "martin"})
	claimsGetter := AddPreValidator(noAuthClaimsGetter, apiKeyValidator)
	ctx := makeContext(map[string]string{
		"x-api-key":     "95thesis",
		"authorization": token,
	})
	claims, err := claimsGetter.Claims(ctx)
	require.NoError(t, err)
	require.Equal(t, martinClaims.Issuer, claims.Issuer)
	require.Equal(t, martinClaims.Subject, claims.Subject)
	require.Len(t, claims.Audience, 1)
	require.Equal(t, martinClaims.Audience, claims.Audience)

	// now bad api-key
	ctx = makeContext(map[string]string{
		"x-api-key":     "fnord",
		"authorization": token,
	})
	_, err = claimsGetter.Claims(ctx)
	require.Error(t, err)

	// api key missing
	ctx = makeContext(map[string]string{
		"authorization": token,
	})
	_, err = claimsGetter.Claims(ctx)
	require.Error(t, err)

	// everything missing
	ctx = makeContext(map[string]string{})
	_, err = claimsGetter.Claims(ctx)
	require.Error(t, err)
}
