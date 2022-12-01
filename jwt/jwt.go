// Copyright © 2022 The lutherauth authors

package jwt

import (
	jwtgo "github.com/golang-jwt/jwt/v4"
)

// NewClaims is a helper to generate a claim object from
// frequently used fields.
func NewClaims(subject string, issuer string, aud string) *Claims {
	claims := &Claims{}
	claims.Audience = jwtgo.ClaimStrings{aud}
	claims.Issuer = issuer
	claims.Subject = subject
	return claims
}

// NewEmptyClaims construcs empty claims with a token, to be populated later.
func NewEmptyClaims(token string) *Claims {
	claims := &Claims{}
	claims.token = token
	return claims
}

// Address is standard OIDC user address.
type Address struct {
	Formatted     string `json:"formatted,omitempty"`
	StreetAddress string `json:"street_address,omitempty"`
	Locality      string `json:"locality,omitempty"`
	Region        string `json:"region,omitempty"`
	PostalCode    string `json:"postal_code,omitempty"`
	Country       string `json:"country,omitempty"`
}

// Claims are Luther-specific claims stored in the JWT.
type Claims struct {
	Username     string   `json:"username"`
	Name         string   `json:"name,omitempty"`
	Groups       []string `json:"luther:groups"`
	Organisation string   `json:"org,omitempty"`
	Email        string   `json:"email"`

	// Nonce used to prevent replay attacks. Hash of a nonce cookie unique to the session.
	Nonce string `json:"nonce,omitempty"`

	jwtgo.RegisteredClaims

	// token contains the original token.
	token string

	// OID Microsoft AD uses OID field as another subject ID.
	OID string `json:"oid,omitempty"`

	FamilyName          string   `json:"family_name,omitempty"`
	GivenName           string   `json:"given_name,omitempty"`
	MiddleName          string   `json:"middle_name,omitempty"`
	Nickname            string   `json:"nickname,omitempty"`
	PreferredUsername   string   `json:"preferred_username,omitempty"`
	Profile             string   `json:"profile,omitempty"`
	Picture             string   `json:"picture,omitempty"`
	Website             string   `json:"website,omitempty"`
	EmailVerified       bool     `json:"email_verified,omitempty"`
	Gender              string   `json:"gender,omitempty"`
	Birthdate           string   `json:"birthdate,omitempty"`
	ZoneInfo            string   `json:"zoneinfo,omitempty"`
	Locale              string   `json:"locale,omitempty"`
	PhoneNumber         string   `json:"phone_number,omitempty"`
	PhoneNumberVerified bool     `json:"phone_number_verified,omitempty"`
	Address             *Address `json:"address,omitempty"`
	UpdatedAt           string   `json:"updated_at,omitempty"`
}

// Duplicate creates a deep copy.
func (c *Claims) Duplicate() *Claims {
	cop := &Claims{
		Username:         c.Username,
		Name:             c.Name,
		Organisation:     c.Organisation,
		Email:            c.Email,
		Nonce:            c.Nonce,
		OID:              c.OID,
		RegisteredClaims: c.RegisteredClaims,
		token:            c.token,
		Groups:           make([]string, len(c.Groups)),
		// OIDC claims
		FamilyName:          c.FamilyName,
		GivenName:           c.GivenName,
		MiddleName:          c.MiddleName,
		Nickname:            c.Nickname,
		PreferredUsername:   c.PreferredUsername,
		Profile:             c.Profile,
		Picture:             c.Picture,
		Website:             c.Website,
		EmailVerified:       c.EmailVerified,
		Gender:              c.Gender,
		Birthdate:           c.Birthdate,
		ZoneInfo:            c.ZoneInfo,
		Locale:              c.Locale,
		PhoneNumber:         c.PhoneNumber,
		PhoneNumberVerified: c.PhoneNumberVerified,
		Address:             c.Address,
		UpdatedAt:           c.UpdatedAt,
	}
	copy(cop.Groups, c.Groups)
	return cop
}

// Token returns the original token that was mapped to the lutherjwt.
func (s *Claims) Token() string {
	return s.token
}
