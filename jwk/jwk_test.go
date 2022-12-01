// Copyright © 2020 The lutherauth authors

package jwk

import (
	"context"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	mrand "math/rand"
	"net/http"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	jwtgo "github.com/golang-jwt/jwt/v4"
	"github.com/mendsley/gojwk"
)

var web bool

func TestMain(m *testing.M) {
	flag.BoolVar(&web, "web", false, "run web tests")
	flag.Parse()
	os.Exit(m.Run())
}

const (
	webKeyURL = "https://cognito-idp.us-west-2.amazonaws.com/us-west-2_sy1c53vOo/.well-known/jwks.json"
	kid       = "f186RI7f4P4PcM3x6fyCxjLJYM3mTVMKRI3P/uKPjPo="
)

// TestWebKeyMatch tests matching a KID within a web key (does not call
// cognito API).
func TestWebKeyMatch(t *testing.T) {
	t.Parallel()
	webKeys := `{"keys":[{"alg":"RS256","e":"AQAB","kid":"3MtnyPz1SH9ddgGlGR73BGifnXKHtszBoH5MDYwDE3E=","kty":"RSA","n":"oZojtGdvqXveYo6nSCDA1cftJPTHTM-MN6FGu46NoVNjhaZvi9X43oFoJ26Vhiel7HrDvIEtg1gsjBNyDhq8zRq6DuYuxasAwtigu7CggYbllLoLEogXKn0jwtaRxp0wAny8geOtd4j2bLfdC6XJwp3FDTP8fxbEt1rkHYpwY77V9xHM_SgT22Q3flVNNrUd3wbVdck8iDR7VkeoZN8r12Dnb_wf5cxSRMbbrKPF-lLiln6ajVHmNPPKunoEM8X8ulMxcz_pC7lvHAykq1YE5Af3dS8alRUuOGk95OBVqVrm28aAQZCTibPPafFgsPjJEhnLj57EoFweY2JNuWEzLw","use":"sig"},{"alg":"RS256","e":"AQAB","kid":"f186RI7f4P4PcM3x6fyCxjLJYM3mTVMKRI3P/uKPjPo=","kty":"RSA","n":"oRZUv9auxYb17cofs6XZaVKNf1iiTFZFjJDXjLCFgxyPn5bF_cxFSYfHjmmbqfCVk0vkzQMReCTTQH6STdllwVsNCTXXLBTN4UvbVkxTqNyRWCOQMvR3KjN6X48EQ3gUCppVGt0dLGZIEYcZbwhnWA1YAdWWWKmO-9V_6Y_9OOC0bDn6h7BKUmVSh-KE5kAAqZDH32B7Z-39jX4EDUgc0X96mruV9zsHnbOD5Z_FiG6OWSGg9wgKUC_bAOCKP7cDAC8_8TxuLhMfU6usr__P69XBCvw9SFbvyXi87UbIPoJnH8BqScNHkYOBD4eANjfWk-xjIgcNVRfaMd6t7Ul2-Q","use":"sig"}]}`
	wk, err := gojwk.Unmarshal([]byte(webKeys))
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
	// fail to match
	_, _, err = matchKID(wk, "")
	if err == nil {
		t.Fatalf("expected error")
	}
	// success to match
	_, _, err = matchKID(wk, kid)
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
}

// TestRetrieveWebKey tests grabbing web keys from a known URL.
// IMPORTANT: this requires internet and the URL to be up!
// run with -web to enable this test!
func TestRetrieveWebKey(t *testing.T) {
	t.Parallel()
	if !web {
		t.Skip("skipping internet test.")
	}
	// success to retrieve keys
	keys, err := retrieveWebKeys(&http.Client{}, webKeyURL)
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
	if len(keys.Keys) == 0 {
		t.Fatalf("expected keys")
	}

	// success to match
	e, n, err := matchKID(keys, kid)
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
	sign, err := makeSignKey(e, n)
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
	_ = sign
}

func TestKeyCache(t *testing.T) {
	t.Parallel()
	cache := newKeyCache(context.Background())
	k := cache.getKey("luther", "a123")
	if k != nil {
		t.Fatalf("expected empty cache")
	}
	kp := MakeTestKey()
	cache.putKey("luther", "a123", kp.PubKey.(*rsa.PublicKey))
	k = cache.getKey("luther", "a123")
	if k != kp.PubKey {
		t.Fatalf("key mismatch")
	}
}

type TestClaims struct {
	jwtgo.RegisteredClaims
}

type testClaimsOID struct {
	jwtgo.RegisteredClaims
	OID string `json:"oid"`
}

func mapIntToClaimDate(t int64) *jwtgo.NumericDate {
	if t == 0 {
		return nil
	}
	return &jwtgo.NumericDate{
		Time: time.Unix(t, 0),
	}
}

func makeClaim(sub string, iss string, aud string, exp int64, iat int64, nbf int64) *TestClaims {
	claims := &TestClaims{}
	claims.Subject = sub
	claims.Issuer = iss
	claims.Audience = jwtgo.ClaimStrings{aud}
	claims.ExpiresAt = mapIntToClaimDate(exp)
	claims.IssuedAt = mapIntToClaimDate(iat)
	claims.NotBefore = mapIntToClaimDate(nbf)
	return claims
}

func cmpClaims(t *testing.T, a jwtgo.Claims, b jwtgo.Claims) {
	aS, ok := a.(*TestClaims)
	if !ok {
		t.Fatalf("invalid claim type")
	}
	bS, ok := b.(*TestClaims)
	if !ok {
		t.Fatalf("invalid claim type")
	}
	if aS.Subject != bS.Subject || aS.Issuer != bS.Issuer || !reflect.DeepEqual(aS.Audience, bS.Audience) {
		t.Fatalf("unexpected subject")
	}
}

type issuerKeys struct {
	pubKeys *gojwk.Key                 // public keys for an issuer
	prvKeys map[string]*rsa.PrivateKey // associated private keys
}

func makeIssuerJWKS(numKeys int) *issuerKeys {
	var keys []*Key
	prvKeys := make(map[string]*rsa.PrivateKey)
	for i := 0; i < numKeys; i++ {
		k := MakeTestKey()
		keys = append(keys, k)
		prvKeys[k.Kid] = k.PrvKey
	}
	return &issuerKeys{
		pubKeys: MakeJWKS(keys),
		prvKeys: prvKeys,
	}
}

func randomKID(keys *gojwk.Key) string {
	if len(keys.Keys) == 0 {
		return keys.Kid
	}
	var kids []string
	for _, k := range keys.Keys {
		kids = append(kids, k.Kid)
	}
	return kids[mrand.Intn(len(kids))]
}

type tokenClaimsTest struct {
	token     string      // JWK token
	claims    *TestClaims // expected claims
	err       error       // expected err
	someError bool        // expect any error
}

func allIssuerOption(allIssuerKeys map[string]*issuerKeys, delay time.Duration) Option {
	return WithRetrieveWebKeysFn(func(iss string) (*gojwk.Key, error) {
		time.Sleep(delay)
		issuer, ok := allIssuerKeys[iss]
		if !ok {
			return nil, fmt.Errorf("unexpected issuer: %s", iss)
		}
		return issuer.pubKeys, nil
	})
}

type issuerTest struct {
	id   string // ID of the issuer
	keys int    // number of keys for the issuer's JWKS
}

type claimsTest struct {
	sub string // subject
	iss string // issuer ID
	aud string // audience
	exp int64  // expiresAt
	iat int64  // issuedAt
	nbf int64  // notBefore
	err bool   // should error?
}

func runValidateTest(t *testing.T, issuerTestTable []issuerTest, claimsTestTable []claimsTest, delay time.Duration, opts ...Option) {

	// create keys for the issuers
	allIssuerKeys := make(map[string]*issuerKeys)
	for _, iss := range issuerTestTable {
		allIssuerKeys[iss.id] = makeIssuerJWKS(iss.keys)
	}

	// create tokens and claims for users, drawing random valid keys from
	// the specified issuer.
	var tests []*tokenClaimsTest
	for _, tc := range claimsTestTable {
		claims := makeClaim(tc.sub, tc.iss, tc.aud, tc.exp, tc.iat, tc.nbf)
		issuer := allIssuerKeys[tc.iss]
		kid := randomKID(issuer.pubKeys)
		if kid == "" {
			panic("missing kid")
		}
		prvKey := issuer.prvKeys[kid]
		token, err := NewJWK(prvKey, claims, kid)
		if err != nil {
			t.Fatalf("unexpected error: %s", err)
		}
		test := &tokenClaimsTest{
			token:     token,
			claims:    claims,
			err:       nil,
			someError: tc.err,
		}
		tests = append(tests, test)
	}

	opts = append([]Option{allIssuerOption(allIssuerKeys, delay)}, opts...)
	settings := NewSettings(opts...)

	// now validate those tokens and make sure claims match
	for _, test := range tests {
		gotStandardClaims, err := ValidateRS256(settings, &TestClaims{}, test.token)
		if test.someError {
			if err == nil {
				t.Fatalf("expected some error")
			}
		} else {
			if test.err == nil && err != nil {
				t.Fatalf("unexpected error: %s", err)
			}
		}
		if !test.someError && err != test.err {
			t.Fatalf("unexpected error: got %s != expected %s", err, test.err)
		}
		if err == nil {
			cmpClaims(t, gotStandardClaims, test.claims)
		}
	}
}

var issuerTestTable = []issuerTest{
	{"org1", 1},
	{"org2", 3},
	{"luther", 5},
}

var claimsTestTable = []claimsTest{
	{"chris", "org1", "luther", 0, 0, 0, false},
	{"bobby", "org1", "luther", 0, 0, 0, false},
	{"john", "org1", "luther", 0, 0, 0, false},
	{"martin", "org2", "luther", 0, 0, 0, false},
	{"louis", "luther", "luther", 0, 0, 0, false},
	{"sam", "luther", "luther", 0, 0, 0, false},
	{"bryan", "luther", "luther", 0, 0, 0, false},
	{"andrei", "luther", "luther", 0, 0, 0, false},
	{"andrei", "luther", "luther", 1, 0, 0, true},                                       // now is really after expAt
	{"andrei", "luther", "luther", time.Now().Unix() - 300, 0, 0, true},                 // now is after expAt
	{"andrei", "luther", "luther", time.Now().Unix() + 10, 0, 0, false},                 // now is within drift
	{"andrei", "luther", "luther", time.Now().Unix(), time.Now().Unix() + 300, 0, true}, // iat > exp
	{"andrei", "luther", "luther", time.Now().Unix() + 90, time.Now().Unix(), 0, false}, // iat < exp
	{"andrei", "luther", "luther", 0, 0, time.Now().Unix() + 300, true},                 // nbf < now
	{"andrei", "luther", "luther", 0, 0, time.Now().Unix() - 90, false},                 // nbf > now
}

func TestValidateJWK(t *testing.T) {
	t.Parallel()
	runValidateTest(t, issuerTestTable, claimsTestTable, 100*time.Millisecond)
}

func TestValidateJWKCache(t *testing.T) {
	t.Parallel()
	opt, fn := WithCacheContext(context.Background())
	defer fn()
	runValidateTest(t, issuerTestTable, claimsTestTable, 100*time.Millisecond, opt)
}

func TestSigValidation(t *testing.T) {
	kp1 := MakeTestKey()
	claims := &TestClaims{}
	claims.Subject = "wat"
	token, err := NewJWK(kp1.PrvKey, claims, "kid")
	fmt.Println(string(token))
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
	_, err = parseClaims(token, kp1.PubKey.(*rsa.PublicKey), true, &TestClaims{})
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
	kp2 := MakeTestKey()
	_, err = parseClaims(token, kp2.PubKey.(*rsa.PublicKey), true, &TestClaims{})
	if err == nil {
		t.Fatalf("expected error!")
	}
	// try cracking open the token and mutating a claim
	fields := strings.Split(string(token), ".")
	if len(fields) != 3 {
		t.Fatalf("expected 3 fields in token")
	}
	t.Run("do not change anything", func(t *testing.T) {
		claims.Subject = "wat"
		b, err := json.Marshal(claims)
		if err != nil {
			t.Fatalf("unexpected error: %s", err)
		}
		fields[1] = base64.RawStdEncoding.EncodeToString(b)
		mutatedToken := strings.Join(fields, ".")
		_, err = parseClaims(mutatedToken, kp1.PubKey.(*rsa.PublicKey), true, &TestClaims{})
		if err != nil {
			t.Fatalf("unexpected error: %s", err)
		}
	})
	t.Run("now mutate the subject", func(t *testing.T) {
		claims.Subject = "wat1"
		b, err := json.Marshal(claims)
		if err != nil {
			t.Fatalf("unexpected error: %s", err)
		}
		fields[1] = base64.RawStdEncoding.EncodeToString(b)
		mutatedToken := strings.Join(fields, ".")
		_, err = parseClaims(mutatedToken, kp1.PubKey.(*rsa.PublicKey), true, &TestClaims{})
		if err == nil {
			t.Fatalf("expected error!")
		}
	})
	t.Run("orig subject, mutate audience", func(t *testing.T) {
		claims.Subject = "wat"
		claims.Audience = jwtgo.ClaimStrings{"fnord"}
		b, err := json.Marshal(claims)
		if err != nil {
			t.Fatalf("unexpected error: %s", err)
		}
		fields[1] = base64.RawStdEncoding.EncodeToString(b)
		mutatedToken := strings.Join(fields, ".")
		_, err = parseClaims(mutatedToken, kp1.PubKey.(*rsa.PublicKey), true, &TestClaims{})
		if err == nil {
			t.Fatalf("expected error!")
		}
	})
	t.Run("try a struct that has more than standard claims", func(t *testing.T) {
		claims := &testClaimsOID{}
		claims.Subject = "wat"
		b, err := json.Marshal(claims)
		if err != nil {
			t.Fatalf("unexpected error: %s", err)
		}
		fields[1] = base64.RawStdEncoding.EncodeToString(b)
		mutatedToken := strings.Join(fields, ".")
		_, err = parseClaims(mutatedToken, kp1.PubKey.(*rsa.PublicKey), true, &TestClaims{})
		if err == nil {
			t.Fatalf("expected error!")
		}
	})
	t.Run("create new token that has more fields", func(t *testing.T) {
		claims := &testClaimsOID{}
		claims.Subject = "wat"
		token2, err := NewJWK(kp1.PrvKey, claims, "kid")
		if err != nil {
			t.Fatalf("unexpected error: %s", err)
		}
		if token2 == token {
			t.Fatalf("expected more claims in token")
		}
		// NOTE: the oid field is contained in the token as "", and NOT omitted
		fmt.Println(string(token2))
		_, err = parseClaims(token2, kp1.PubKey.(*rsa.PublicKey), true, &TestClaims{})
		if err != nil {
			// NOTE: somehow the library still validates the token even though TestClaims
			// is a subset!
			t.Fatalf("unexpected error: %s", err)
		}
		claims.OID = "fnord"
		b, err := json.Marshal(claims)
		if err != nil {
			t.Fatalf("unexpected error: %s", err)
		}
		fields[1] = base64.RawStdEncoding.EncodeToString(b)
		mutatedToken := strings.Join(fields, ".")
		_, err = parseClaims(mutatedToken, kp1.PubKey.(*rsa.PublicKey), true, &TestClaims{})
		if err == nil {
			// NOTE: somehow the library still validates the token even though TestClaims
			// is a subset!
			t.Fatalf("expected error!")
		}
	})
}
