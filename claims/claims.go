// Copyright © 2022 The lutherauth authors

// Package claims provides claim extraction and validation of tokens and keys.
package claims

import (
	"context"
	"encoding/base64"
	"encoding/json"

	"github.com/luthersystems/lutherauth-sdk-go/jwk"
	"github.com/luthersystems/lutherauth-sdk-go/jwt"
	"github.com/sirupsen/logrus"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Getter gets claims from a context.
type Getter interface {
	// if any error is generated, it MUST be a GRPC status.Status-based error
	Claims(ctx context.Context) (claims *jwt.Claims, err error)
}

// GRPCClaims gets claims and returns GRPC errors.
type GRPCClaims struct {
	claimsGetter Getter
	// logger gets a logrus logger. This is needed since GRPCClaims overrides
	// the existing error message with a minimal GRPC one that does not leak
	// (possibly) sensitive data.
	logger func(ctx context.Context) *logrus.Entry
}

// NewGRPCClaims returns a struct that gets claims from a GRPC context.
func NewGRPCClaims(claimsGetter Getter, logger func(ctx context.Context) *logrus.Entry) *GRPCClaims {
	return &GRPCClaims{
		claimsGetter: claimsGetter,
		logger:       logger,
	}
}

// Claims gets claims from a GRPC context.
func (s *GRPCClaims) Claims(ctx context.Context) (*jwt.Claims, error) {
	claims, err := s.claimsGetter.Claims(ctx)
	if err == nil && claims == nil {
		err = status.Error(codes.Internal, "no error but no claims either")
	}
	if err != nil {
		s.logger(ctx).WithError(err).Debugf("auth fail")
		return nil, err
	}
	return claims, nil
}

// fakeAuthClaims extracts unauthenticated json claims from an authorization header.
type fakeAuthClaims struct {
	tokenGetter TokenGetter
}

// NewFakeAuthClaims returns a claims getter without authentication.
func NewFakeAuthClaims(tokenGetter TokenGetter) Getter {
	return &fakeAuthClaims{tokenGetter: tokenGetter}
}

// Claims implements Getter.
func (s *fakeAuthClaims) Claims(ctx context.Context) (*jwt.Claims, error) {
	token, err := s.tokenGetter(ctx)
	if err != nil {
		return nil, err
	}
	jsonToken, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil {
		return nil, status.Error(codes.Unauthenticated, "could not decode token (base64 step)")
	}
	claims := jwt.NewEmptyClaims(token)
	err = json.Unmarshal([]byte(jsonToken), &claims)
	if err != nil {
		return nil, status.Error(codes.Unauthenticated, "could not decode token (JSON step)")
	}
	return claims, nil
}

// NewFakeAuthToken constructs a token compatible with the FakeAuthClaims.
func NewFakeAuthToken(claims *jwt.Claims) string {
	jsonBytes, err := json.Marshal(claims)
	if err != nil {
		return ""
	}
	return base64.RawURLEncoding.EncodeToString(jsonBytes)
}

type jwkClaims struct {
	tokenGetterAuth TokenGetter
	tokenGetterCSRF TokenGetter
	// logger gets a logrus logger. This is needed since validation
	// errors cannot be wrapped in GRPC errors.
	logger   func(ctx context.Context) *logrus.Entry
	settings *jwk.Settings
}

// NewJWKClaims returns a Getter that uses JWKs for authentication.
func NewJWKClaims(tokenGetterAuth TokenGetter, tokenGetterCSRF TokenGetter, logger func(ctx context.Context) *logrus.Entry, opts ...jwk.Option) Getter {
	return &jwkClaims{
		tokenGetterAuth: tokenGetterAuth,
		tokenGetterCSRF: tokenGetterCSRF,
		logger:          logger,
		settings:        jwk.NewSettings(opts...),
	}
}

// Claims implements Getter.
func (s *jwkClaims) Claims(ctx context.Context) (*jwt.Claims, error) {
	token, err := s.tokenGetterAuth(ctx)
	if err != nil {
		return nil, status.Error(codes.Unauthenticated, "could not read token")
	}
	claims := jwt.NewEmptyClaims(token)
	gotClaims, err := jwk.ValidateRS256(s.settings, claims, token)
	if err != nil {
		s.logger(ctx).WithError(err).Debugf("validation failed")
		return nil, status.Error(codes.Unauthenticated, "could not validate token")
	}
	if s.tokenGetterCSRF != nil && claims.Nonce != "" {
		nonce, err := s.tokenGetterCSRF(ctx)
		if err != nil {
			return nil, status.Error(codes.Unauthenticated, "could not read CSRF token/nonce")
		}
		if nonce != claims.Nonce {
			return nil, status.Error(codes.Unauthenticated, "could not validate CSRF token/nonce")
		}
	}
	claims, ok := gotClaims.(*jwt.Claims)
	if !ok {
		return nil, status.Error(codes.Internal, "could not cast token")
	}
	return claims, nil
}
