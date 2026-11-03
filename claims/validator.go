// Copyright © 2022 The lutherauth authors

package claims

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"

	"github.com/luthersystems/lutherauth-sdk-go/jwt"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// PreValidator executes before claims are extracted from a token.
type PreValidator interface {
	Validate(ctx context.Context) error
}

type apiKeyValidator struct {
	tokenGetter TokenGetter
	// digests are SHA-256 digests of the keys. Comparing fixed-size
	// digests keeps the time the same whatever the key lengths are;
	// ConstantTimeCompare returns at once on a length mismatch.
	digests [][sha256.Size]byte
}

// NewAPIKeyValidator validates a valid API key is present.
func NewAPIKeyValidator(tokenGetter TokenGetter, keys []string) PreValidator {
	// Digests compared in constant time, not a map: a map lookup's time
	// depends on the key, and these are secrets. An empty entry (for
	// example from splitting an empty setting) is dropped, so it can never
	// match an empty key.
	digests := make([][sha256.Size]byte, 0, len(keys))
	for _, k := range keys {
		if k != "" {
			digests = append(digests, sha256.Sum256([]byte(k)))
		}
	}
	return &apiKeyValidator{
		tokenGetter: tokenGetter,
		digests:     digests,
	}
}

// Validate implemnts PreValidator.
func (s *apiKeyValidator) Validate(ctx context.Context) error {
	apiKey, err := s.tokenGetter(ctx)
	if err != nil {
		return err
	}
	got := sha256.Sum256([]byte(apiKey))
	ok := false
	for _, k := range s.digests {
		// Check every key, so the time does not show which one matched.
		if subtle.ConstantTimeCompare(got[:], k[:]) == 1 {
			ok = true
		}
	}
	if !ok {
		return status.Error(codes.Unauthenticated, "API key not recognized")
	}
	return nil
}

type claimsGetterAndPreValidator struct {
	claimsGetter Getter
	validator    PreValidator
}

// AddPreValidator adds pre-validation to a claim getter. The specified
// validator must resolve true before claim extraction occurs.
func AddPreValidator(claimsGetter Getter, validator PreValidator) Getter {
	return &claimsGetterAndPreValidator{claimsGetter: claimsGetter, validator: validator}
}

// Claims impelments Getter.
func (s *claimsGetterAndPreValidator) Claims(ctx context.Context) (*jwt.Claims, error) {
	err := s.validator.Validate(ctx)
	if err != nil {
		return nil, err
	}
	return s.claimsGetter.Claims(ctx)
}
