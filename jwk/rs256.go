// Copyright © 2020 The lutherauth authors

package jwk

import (
	"context"
	"crypto"
	"crypto/rsa"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"sync"
	"time"

	jwtgo "github.com/golang-jwt/jwt/v4"
	"github.com/mendsley/gojwk"
	"github.com/sirupsen/logrus"
)

// parseClaims parses a token for claims, and validates using a signature key.
func parseClaims(tokenString string, pubKey *rsa.PublicKey, validate bool, claims jwtgo.Claims) (*jwtgo.Token, error) {
	var parser *jwtgo.Parser
	alg := jwtgo.SigningMethodRS256.Name
	if validate {
		parser = jwtgo.NewParser(jwtgo.WithValidMethods([]string{alg}))
	} else {
		parser = jwtgo.NewParser(jwtgo.WithValidMethods([]string{alg}), jwtgo.WithoutClaimsValidation())
	}

	token, err := parser.ParseWithClaims(tokenString, claims, func(token *jwtgo.Token) (verifykey interface{}, err error) {
		return pubKey, nil
	})

	if err != nil {
		if errors.Is(err, jwtgo.ErrTokenMalformed) {
			return nil, fmt.Errorf("malformed token: %w", err)
		}
		if errors.Is(err, jwtgo.ErrTokenSignatureInvalid) {
			return nil, fmt.Errorf("invalid signature: %w", err)
		}
		if errors.Is(err, jwtgo.ErrTokenExpired) {
			return nil, fmt.Errorf("expired token: %w", err)
		}
		return nil, fmt.Errorf("token validation failed: %w", err)
	}

	if token == nil {
		return nil, fmt.Errorf("nil jwk token")
	}
	if !token.Valid {
		return nil, fmt.Errorf("invalid jwk token")
	}
	return token, nil
}

// retrieveWebKeys is a helper that returns web keys.
func retrieveWebKeys(httpClient *http.Client, url string) (*gojwk.Key, error) {
	res, err := httpClient.Get(url)
	if err != nil {
		return nil, fmt.Errorf("get JWKS (%s): %s", url, err)
	}
	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("bad status (%s): code: %d", url, res.StatusCode)
	}
	body, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, fmt.Errorf("read JWKS (%s) JSON: %s", url, err)
	}
	keys, err := gojwk.Unmarshal(body)
	if err != nil {
		return nil, fmt.Errorf("unmarshal JWKS (%s): %s", url, err)
	}
	return keys, nil
}

// makeSignKey returns a RSA public key given n,e of a jwt token
func makeSignKey(rawE string, rawN string) (*rsa.PublicKey, error) {
	decodedE, err := base64.RawURLEncoding.DecodeString(rawE)
	if err != nil {
		return nil, fmt.Errorf("error decoding rawE public key")
	}
	if len(decodedE) < 4 {
		ndata := make([]byte, 4)
		copy(ndata[4-len(decodedE):], decodedE)
		decodedE = ndata
	}
	pubKey := &rsa.PublicKey{
		N: &big.Int{},
		E: int(binary.BigEndian.Uint32(decodedE[:])),
	}
	decodedN, err := base64.RawURLEncoding.DecodeString(rawN)
	if err != nil {
		return nil, fmt.Errorf("error decoding rawN public key")
	}
	pubKey.N.SetBytes(decodedN)
	return pubKey, nil
}

// matchKID returns the N,E values of a JWK if kid matches one of the kids in
// the webs keys.
// Returns the raw E and N values associated with the matched JWT
func matchKID(keys *gojwk.Key, kid string) (string, string, error) {
	if kid == "" {
		return "", "", fmt.Errorf("no kid")
	}
	var rawE, rawN string
	var kidMatch = false
	if keys.Kid == kid {
		kidMatch = true
		rawE = keys.E
		rawN = keys.N
	} else {
		for _, k := range keys.Keys {
			if k.Kid == kid {
				kidMatch = true
				rawE = k.E
				rawN = k.N
				break
			}
		}
	}
	if !kidMatch {
		return "", "", fmt.Errorf("missing kid [%s] in web keys", kid)
	}
	return rawE, rawN, nil
}

var defaultCacheDuration time.Duration = 10 * time.Minute
var defaultCacheExpirePoll time.Duration = 1 * time.Minute

type cacheItem struct {
	key      *rsa.PublicKey
	insertAt time.Time
}

type keyCache struct {
	m  sync.RWMutex
	wg sync.WaitGroup

	ctx    context.Context
	doneFn context.CancelFunc

	ttl  time.Duration
	poll time.Duration
	keys map[string]*cacheItem

	// now is used for testing
	now func() time.Time
}

func newKeyCache(ctx context.Context) *keyCache {
	ctx, doneFn := context.WithCancel(ctx)
	s := &keyCache{
		ctx:    ctx,
		doneFn: doneFn,
		keys:   make(map[string]*cacheItem),
		ttl:    defaultCacheDuration,
		poll:   defaultCacheExpirePoll,
		now:    time.Now,
	}

	s.startExpirePoll()

	return s
}

func (s *keyCache) startExpirePoll() {
	ticker := time.NewTicker(s.poll)
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		for {
			select {
			case <-s.ctx.Done():
				return
			case <-ticker.C:
				s.purgeExpired()
			}
		}
	}()
}

// stopExpirePoll blocks the caller until the cache go routine has stopped.
func (s *keyCache) stopExpirePoll() {
	if s.doneFn != nil {
		s.doneFn()
	}
	s.wg.Wait()
}

func makeCacheKey(issuer string, kid string) string {
	return fmt.Sprintf("%s^%s", issuer, kid)
}

func (s *keyCache) purgeExpired() {
	s.m.Lock()
	defer s.m.Unlock()

	for k, item := range s.keys {
		if s.expired(item) {
			delete(s.keys, k)
		}
	}
}

func (s *keyCache) expired(item *cacheItem) bool {
	if item == nil {
		return true
	}
	return s.now().Sub(item.insertAt) > s.ttl
}

func (s *keyCache) getKey(issuer string, kid string) *rsa.PublicKey {
	s.m.RLock()
	defer s.m.RUnlock()

	item := s.keys[makeCacheKey(issuer, kid)]
	if s.expired(item) {
		return nil
	}
	return item.key
}

func (s *keyCache) putKey(issuer string, kid string, key *rsa.PublicKey) {
	s.m.Lock()
	defer s.m.Unlock()

	s.keys[makeCacheKey(issuer, kid)] = &cacheItem{
		key:      key,
		insertAt: s.now(),
	}
}

// Settings configure the jwk library.
type Settings struct {
	cache               *keyCache
	retrieveWebKeysFn   func(issuer string) (*gojwk.Key, error)
	issuerToWebKeyURLFn func(issuer string) (string, error)
	httpClient          *http.Client
	getNow              func() time.Time // Allows us to mock the current time
}

func (s *Settings) getKey(issuer string, kid string) *rsa.PublicKey {
	if s.cache == nil || issuer == "" || kid == "" {
		return nil
	}
	return s.cache.getKey(issuer, kid)
}

func (s *Settings) putKey(issuer string, kid string, key *rsa.PublicKey) {
	if s.cache == nil || issuer == "" || kid == "" || key == nil {
		return
	}
	s.cache.putKey(issuer, kid, key)
}

func newHTTPClient() *http.Client {
	var netTransport = &http.Transport{
		Dial: (&net.Dialer{
			Timeout: 5 * time.Second,
		}).Dial,
		TLSHandshakeTimeout: 5 * time.Second,
		Proxy:               http.ProxyFromEnvironment,
	}
	return &http.Client{
		Timeout:   time.Second * 10,
		Transport: netTransport,
	}
}

func (s *Settings) retrieveWebKeys(issuer string) (*gojwk.Key, error) {
	if issuer == "" {
		return nil, errors.New("invalid issuer")
	}
	if s.retrieveWebKeysFn == nil && s.issuerToWebKeyURLFn == nil {
		return nil, errors.New("missing all web key fns")
	}
	if s.issuerToWebKeyURLFn == nil {
		return s.retrieveWebKeysFn(issuer)
	}

	webKeyURL, err := s.issuerToWebKeyURLFn(issuer)

	if err != nil {
		if s.retrieveWebKeysFn == nil {
			return nil, fmt.Errorf(
				"retrieveWebKeysFn is not defined, and issuerToWebKeyURLFn failed: %w", err,
			)
		}
		return s.retrieveWebKeysFn(issuer)
	}

	if webKeyURL == "" {
		if s.retrieveWebKeysFn == nil {
			return nil, errors.New("retrieveWebKeysFn is not defined and webKeyURL is empty")
		}
		return s.retrieveWebKeysFn(issuer)
	}

	client := s.httpClient
	if client == nil {
		client = newHTTPClient()
	}

	return retrieveWebKeys(client, webKeyURL)
}

// CancelWaitFunc cancels the expiration go routine and blocks until it exits.
type CancelWaitFunc func()

// Option lets you configure JWK validation.
type Option func(s *Settings)

// WithCache enables caching of keys.
// Deprecated: WithCache will be removed in a later version.
// Use WithCacheContext.
func WithCache() Option {
	opt, _ := WithCacheContext(context.TODO())
	return opt
}

// WithCacheContext enables caching of keys and a cancel context.
// Calling the cancel function on the context will stop the cache expiration
// go routine.
func WithCacheContext(ctx context.Context) (Option, CancelWaitFunc) {
	var kc *keyCache
	return func(s *Settings) {
			s.cache = newKeyCache(ctx)
			kc = s.cache
		}, func() {
			if kc == nil {
				return
			}
			kc.stopExpirePoll()
		}
}

// WithHardcodedKey allows specifying a hardcoded public key that is used for
// JWKS key retrieval.
func WithHardcodedKey(pubKey crypto.PublicKey, kid string) Option {
	return WithRetrieveWebKeysFn(func(issuer string) (*gojwk.Key, error) {
		k, err := gojwk.PublicKey(pubKey)
		if err != nil {
			return nil, err
		}
		k.Kid = kid
		return k, nil
	})
}

// WithRetrieveWebKeysFn allows specifying a custom function to retrieve keys.
// If this function is specified with WithIssuerWebKeyURL, then it will only be
// called if WithIssuerWebKeyURL cannot resolve the URL.
func WithRetrieveWebKeysFn(retrieveWebKeysFn func(issuer string) (*gojwk.Key, error)) Option {
	return func(s *Settings) {
		oldFn := s.retrieveWebKeysFn
		s.retrieveWebKeysFn = func(issuer string) (*gojwk.Key, error) {
			if oldFn != nil {
				key, err := oldFn(issuer)
				if err != nil {
					logrus.WithError(err).Debug("retrieveWebKeysFn")
				} else if key != nil {
					return key, nil
				}
			}

			return retrieveWebKeysFn(issuer)
		}
	}
}

// WithIssuerToWebKeyURL allows specifying a custom function to map an issuer id
// to a URL that has keys (JWKS).
// This function handler takes precedence over WithRetrieveWebKeysFn.
// You can pass multiple options in which case they'll be evaluated in the order
// they are passed, and the first successful response is returned.
func WithIssuerToWebKeyURL(issuerToWebKeyURLFn func(issuer string) (string, error)) Option {
	return func(s *Settings) {
		oldFn := s.issuerToWebKeyURLFn
		s.issuerToWebKeyURLFn = func(issuer string) (string, error) {
			if oldFn != nil {
				url, err := oldFn(issuer)
				if err != nil {
					logrus.WithError(err).Debug("issuerToWebKeyURLFn")
				} else if url != "" {
					return url, nil
				}
			}

			return issuerToWebKeyURLFn(issuer)
		}
	}
}

// WithHTTPClient allows specifying a custom http client used to retrieve
// web keys.
func WithHTTPClient(httpClient *http.Client) Option {
	return func(s *Settings) {
		s.httpClient = httpClient
	}
}

func WithNowFunction(t func() time.Time) Option {
	return func(s *Settings) {
		s.getNow = t
	}
}

// NewSettings returns settings to validate JWKs.
func NewSettings(opts ...Option) *Settings {
	settings := &Settings{
		getNow: time.Now,
	}
	for _, opt := range opts {
		opt(settings)
	}
	return settings
}

const okSkew = 60 * 2 * time.Second

func isBeforeWithDrift(t1, t2 time.Time) bool {
	return t1.Before(t2.Add(okSkew))
}

func isAfterWithDrift(t1, t2 time.Time) bool {
	return t1.Add(okSkew).After(t2)
}

// ValidateRS256 validates a RS256 JWK and returns the claims if valid.
// IMPORTANT: This does not validate the issuer.
func ValidateRS256(settings *Settings, claims jwtgo.Claims, token string) (jwtgo.Claims, error) {
	if token == "" {
		return nil, fmt.Errorf("missing token")
	}
	parser := &jwtgo.Parser{}
	parsedToken, _, err := parser.ParseUnverified(token, &jwtgo.RegisteredClaims{})
	if err != nil {
		return nil, err
	}
	// Grab claims *WITHOUT* validation (we need the issuer, kid first)
	regClaims, ok := parsedToken.Claims.(*jwtgo.RegisteredClaims)
	if !ok {
		return nil, fmt.Errorf("invalid claim type")
	}
	issuer := regClaims.Issuer
	if issuer == "" {
		return nil, fmt.Errorf("missing issuer")
	}
	alg, ok := parsedToken.Header["alg"].(string)
	if !ok || alg != "RS256" {
		return nil, fmt.Errorf("unsupported alg: [%s]", alg)
	}
	kid, ok := parsedToken.Header["kid"].(string)
	if !ok || kid == "" {
		return nil, fmt.Errorf("invalid kid: [%s]", kid)
	}

	{
		// Short-circuit certain claim validation to avoid expensive JWK lookup
		// IMPORTANT: this is just initial validation, and JWK library will validate
		// these claims as well, possibly more strictly.
		// Indeed, as of Apr2018 jwt-go does NOT allow clock skew (e.g., it rejects
		// tokens that expire 1s in the past).
		// That library also validates the `iat` against the current time, which does
		// not appear to be part of RFC 7519.

		now := settings.getNow()

		if regClaims.ExpiresAt != nil {
			// RFC 7519: https://tools.ietf.org/html/rfc7519#section-4.1.4
			// The processing of the "exp" claim requires that the current date/time
			// MUST be before the expiration date/time listed in the "exp" claim.
			if !isAfterWithDrift(regClaims.ExpiresAt.Time, now) {
				return nil, fmt.Errorf("jwt expired at (exp) [%d] <= now [%d]", regClaims.ExpiresAt.Time.Unix(), now.Unix())
			}
			if regClaims.IssuedAt != nil && !isBeforeWithDrift(regClaims.IssuedAt.Time, regClaims.ExpiresAt.Time) {
				// This indicates something wrong with the IDP configuration, but is not
				// a requirement by RFC7519.
				return nil, fmt.Errorf("jwt issued at (iat) [%d] >= expires at (exp) [%d]", regClaims.IssuedAt.Time.Unix(), regClaims.ExpiresAt.Unix())
			}
		}

		if regClaims.NotBefore != nil {
			// RFC 7519: https://tools.ietf.org/html/rfc7519#section-4.1.4
			// The processing of the "nbf" claim requires that the current date/time MUST
			// be after or equal to the not-before date/time listed in the "nbf" claim.
			// Implementers MAY provide for some small leeway, usually no more than a few minutes, to
			// account for clock skew.
			if !isAfterWithDrift(now, regClaims.NotBefore.Time) {
				return nil, fmt.Errorf("jwt received too early (now) [%d] <= nbf [%d]", now.Unix(), regClaims.NotBefore.Time.Unix())
			}
		}
	}

	signKey := settings.getKey(issuer, kid)
	if signKey != nil {
		// This parses the claims *AND* validates the token
		parsedToken, err := parseClaims(token, signKey, true, claims)
		if err == nil {
			// fast path: we have a good key!
			return parsedToken.Claims, nil
		}
	}

	webKeys, err := settings.retrieveWebKeys(issuer)
	if err != nil {
		return nil, fmt.Errorf("retrieve web key (%s): %v", issuer, err)
	}
	rawE, rawN, err := matchKID(webKeys, kid)
	if err != nil {
		return nil, fmt.Errorf("match KID (%s): %v", issuer, err)
	}
	signKey, err = makeSignKey(rawE, rawN)
	if err != nil {
		return nil, fmt.Errorf("make sign key (%s): %v", issuer, err)
	}

	settings.putKey(issuer, kid, signKey)

	// This parses the claims *AND* validates the token
	parsedToken, err = parseClaims(token, signKey, true, claims)
	if err != nil {
		return nil, fmt.Errorf("validate (%s): %v: %s", issuer, err, token)
	}

	return parsedToken.Claims, nil
}

// NewJWK constructs a RS256 JWT for a set of claims.
func NewJWK(signKey *rsa.PrivateKey, claims jwtgo.Claims, kid string) (string, error) {
	token := jwtgo.NewWithClaims(jwtgo.SigningMethodRS256, claims)
	token.Header["kid"] = kid
	signedToken, err := token.SignedString(signKey)
	if err != nil {
		return "", err
	}
	return signedToken, nil
}
