// Copyright © 2022 The lutherauth authors

package claims

import (
	"context"

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
	keySet      map[string]interface{}
}

// NewAPIKeyValidator validates a valid API key is present.
func NewAPIKeyValidator(tokenGetter TokenGetter, keys []string) PreValidator {
	keySet := make(map[string]interface{}, len(keys))
	var empty interface{}
	for _, k := range keys {
		keySet[k] = empty
	}
	return &apiKeyValidator{
		tokenGetter: tokenGetter,
		keySet:      keySet,
	}
}

// Validate implemnts PreValidator.
func (s *apiKeyValidator) Validate(ctx context.Context) error {
	apiKey, err := s.tokenGetter(ctx)
	if err != nil {
		return err
	}
	_, ok := s.keySet[apiKey]
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
