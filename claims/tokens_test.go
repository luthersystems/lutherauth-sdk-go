// Copyright © 2022 The lutherauth authors

package claims

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestRawTokenGetter(t *testing.T) {
	t.Parallel()
	token := NewFakeAuthToken(martinClaims)
	ctx := makeContext(map[string]string{
		"authorization": token,
	})
	tokenGetter := NewRawTokenGetter("authorization", true)
	gotToken, err := tokenGetter(ctx)
	require.NoError(t, err)
	require.Equal(t, token, gotToken)
}

func TestCookieTokenGetter(t *testing.T) {
	t.Parallel()
	token := "TOKEN"
	cookie := fmt.Sprintf("authorization=%s; Max-Age=86400; Domain=x-staging.luthersystems.com; Path=/; Expires=Tue, 29 Jan 2019 17:15:53 GMT; HttpOnly", token)
	ctx := makeContext(map[string]string{
		"cookie": cookie,
	})
	tokenGetter := NewCookieTokenGetter("authorization", true)
	gotToken, err := tokenGetter(ctx)
	require.NoError(t, err)
	require.Equal(t, token, gotToken)
}

func TestCookieGetter(t *testing.T) {
	t.Parallel()
	token := "TOKEN"
	cookieStr := fmt.Sprintf("authorization=%s; Max-Age=86400; Domain=x-staging.luthersystems.com; Path=/; Expires=Tue, 29 Jan 2019 17:15:53 GMT; HttpOnly", token)
	ctx := makeContext(map[string]string{
		"cookie": cookieStr,
	})
	cookieGetter := NewCookieGetter("authorization", true)
	cookie, err := cookieGetter(ctx)
	require.NoError(t, err)
	require.Equal(t, token, cookie.Value)
}
