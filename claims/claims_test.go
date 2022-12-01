// Copyright © 2022 The lutherauth authors

package claims

import (
	"context"
	"testing"

	jwtgo "github.com/golang-jwt/jwt/v4"
	"github.com/luthersystems/lutherauth-sdk-go/jwk"
	"github.com/luthersystems/lutherauth-sdk-go/jwt"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/metadata"
)

var martinClaims = jwt.NewClaims("martin", "Luther Systems Test IDP", "luther")

func makeContext(headers map[string]string) context.Context {
	return metadata.NewOutgoingContext(context.Background(), metadata.New(headers))
}

type claimsGetterFactory func(tokenGetter TokenGetter) Getter

func validMartinClaims(t *testing.T, getGetter claimsGetterFactory, token string) {
	claimsGetter := getGetter(NewRawTokenGetter("authorization", true))
	ctx := makeContext(map[string]string{
		"authorization": token,
	})
	claims, err := claimsGetter.Claims(ctx)
	require.NoError(t, err)

	require.Equal(t, "Luther Systems Test IDP", claims.Issuer)
	require.Equal(t, "martin", claims.Subject)
	require.Len(t, claims.Audience, 1)
	require.Equal(t, "luther", claims.Audience[0])
	require.Equal(t, claims.Token(), token)
}

func TestFakeAuthClaims(t *testing.T) {
	t.Parallel()
	token := NewFakeAuthToken(martinClaims)
	claimsFactory := func(tokenGetter TokenGetter) Getter {
		return NewFakeAuthClaims(tokenGetter)
	}
	validMartinClaims(t, claimsFactory, token)
}

func TestFakeAuthClaimsMultipleAudience(t *testing.T) {
	t.Parallel()

	claims := &jwt.Claims{}
	claims.Issuer = "Luther Systems Test IDP"
	claims.Subject = "martin"
	claims.Audience = jwtgo.ClaimStrings{"luther", "fnord"}

	token := NewFakeAuthToken(claims)
	claimsFactory := func(tokenGetter TokenGetter) Getter {
		return NewFakeAuthClaims(tokenGetter)
	}
	claimsGetter := claimsFactory(NewRawTokenGetter("authorization", true))
	ctx := makeContext(map[string]string{
		"authorization": token,
	})
	claims, err := claimsGetter.Claims(ctx)
	require.NoError(t, err)

	require.Len(t, claims.Audience, 2)
	require.Equal(t, "luther", claims.Audience[0])
	require.Equal(t, "fnord", claims.Audience[1])
}

func TestJWKClaims(t *testing.T) {
	t.Parallel()

	key := jwk.MakeTestKey()
	token, err := jwk.NewJWK(key.PrvKey, martinClaims, key.Kid)

	require.NoError(t, err)
	opt := jwk.WithHardcodedKey(key.PubKey, key.Kid)
	claimsFactory := func(tokenGetter TokenGetter) Getter {
		return NewJWKClaims(tokenGetter, nil, (func(ctx context.Context) *logrus.Entry { return logrus.NewEntry(logrus.StandardLogger()) }), opt)
	}
	validMartinClaims(t, claimsFactory, token)
}

func TestFakeAuthClaimsAudBackwardsCompat(t *testing.T) {
	t.Parallel()
	// IMPORTANT: this is token with a legacy format that does not have an aud array
	token := "eyJ1c2VybmFtZSI6IiIsIm5hbWUiOiIiLCJsdXRoZXI6Z3JvdXBzIjpudWxsLCJvcmciOiIiLCJlbWFpbCI6IiIsIm5vbmNlIjoiIiwiYXVkIjoibHV0aGVyIiwiaXNzIjoiTHV0aGVyIFN5c3RlbXMgVGVzdCBJRFAiLCJzdWIiOiJtYXJ0aW4iLCJvaWQiOiIifQ" // nolint:gosec
	claimsFactory := func(tokenGetter TokenGetter) Getter {
		return NewFakeAuthClaims(tokenGetter)
	}
	validMartinClaims(t, claimsFactory, token)
}
