// Copyright © 2022 The lutherauth authors

package claims

import (
	"context"
	"net/http"
	"strings"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

const (
	cookieGRPCHeader = "cookie"
)

// TokenGetter gets tokens from a context.
type TokenGetter func(ctx context.Context) (string, error)

// CookieGetter gets tokens from a context.
type CookieGetter func(ctx context.Context) (*http.Cookie, error)

// NewRawTokenGetter gets raw tokens from a GRPC context.
func NewRawTokenGetter(grpcHeader string, outgoing bool) TokenGetter {
	getter := mdGetter(grpcHeader, outgoing)
	return func(ctx context.Context) (string, error) {
		auth, err := getter(ctx)
		if err != nil {
			return "", err
		}
		fields := strings.Fields(auth[0])
		if len(fields) != 1 {
			return "", status.Error(codes.Unauthenticated, "malformed authorization")
		}
		return fields[0], nil
	}
}

func NewAuthTokenGetter() TokenGetter {
	getter := mdGetter("authorization", false)
	return func(ctx context.Context) (string, error) {
		auth, err := getter(ctx)
		if err != nil {
			return "", err
		}
		fields := strings.Fields(auth[0])
		if len(fields) != 2 || fields[0] != "Bearer" {
			return "", status.Error(codes.Unauthenticated, "malformed authorization")
		}
		return fields[1], nil
	}
}

type headerGetter func(context.Context) ([]string, error)

func mdGetter(grpcHeader string, outgoing bool) headerGetter {
	metadataFromContext := metadata.FromIncomingContext
	if outgoing {
		metadataFromContext = metadata.FromOutgoingContext
	}
	grpcHeader = strings.ToLower(grpcHeader)
	return func(ctx context.Context) ([]string, error) {
		if ctx == nil {
			return nil, status.Error(codes.Unauthenticated, "context is nil")
		}
		md, ok := metadataFromContext(ctx)
		if !ok {
			return nil, status.Error(codes.Unauthenticated, "missing metadata")
		}
		auth := md[grpcHeader]
		if len(auth) == 0 {
			return nil, status.Error(codes.Unauthenticated, "empty header")
		}
		return auth, nil
	}
}

// NewCookieTokenGetter gets cookie tokens from a GRPC context.
func NewCookieTokenGetter(cookieName string, outgoing bool) TokenGetter {
	getter := mdGetter(cookieGRPCHeader, outgoing)
	return func(ctx context.Context) (string, error) {
		auth, err := getter(ctx)
		if err != nil {
			return "", err
		}
		cookie, err := cookieGetter(cookieName, auth)
		if err != nil {
			return "", err
		}
		return cookie.Value, nil
	}
}

// NewCookieGetter gets an auth cookie from a GRPC context.
func NewCookieGetter(cookieName string, outgoing bool) CookieGetter {
	getter := mdGetter(cookieGRPCHeader, outgoing)
	return func(ctx context.Context) (*http.Cookie, error) {
		auth, err := getter(ctx)
		if err != nil {
			return nil, err
		}
		return cookieGetter(cookieName, auth)
	}
}

func cookieGetter(cookieName string, auth []string) (*http.Cookie, error) {
	if len(auth) != 1 {
		return nil, status.Error(codes.Unauthenticated, "malformed authorization")
	}
	header := http.Header{}
	header.Add("Cookie", auth[0])
	request := http.Request{
		Header: header,
	}
	cookies := request.Cookies()
	var foundCookie *http.Cookie
	for _, cookie := range cookies {
		if strings.EqualFold(cookie.Name, cookieName) {
			foundCookie = cookie
			break
		}
	}
	if foundCookie == nil {
		return nil, status.Error(codes.Unauthenticated, "missing header")
	}
	// IMPORTANT: for now, we are *NOT* validating cookies!
	return foundCookie, nil
}
