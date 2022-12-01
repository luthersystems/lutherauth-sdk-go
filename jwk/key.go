// Copyright © 2020 The lutherauth authors

package jwk

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"

	"github.com/mendsley/gojwk"
)

// testRSAKeySize is the RSA key size for tests.
const testRSAKeySize = 2048

// MakeTestKey generates a random pub/priv key pair for testing.
func MakeTestKey() *Key {
	prvKey, err := rsa.GenerateKey(rand.Reader, testRSAKeySize)
	if err != nil {
		panic(err)
	}
	pubKey := prvKey.Public()
	if err != nil {
		panic(err)
	}

	kid, err := pubKeyToKID(pubKey)
	if err != nil {
		panic(err)
	}

	return &Key{
		PrvKey: prvKey,
		PubKey: pubKey,
		Kid:    kid,
	}
}

// Key represents a pub/priv RSA key pair.
type Key struct {
	// PrvKey is a private RSA key
	PrvKey *rsa.PrivateKey
	// PubKey is a public RSA key
	PubKey crypto.PublicKey
	// Kid is a key ID
	Kid string
}

func (s *Key) PrvKeyPEM() string {
	return string(
		pem.EncodeToMemory(
			&pem.Block{
				Type:  "RSA PRIVATE KEY",
				Bytes: x509.MarshalPKCS1PrivateKey(s.PrvKey),
			},
		))
}

func pubKeyToKID(pubKey crypto.PublicKey) (string, error) {
	asn1Bytes, err := x509.MarshalPKIXPublicKey(pubKey)
	if err != nil {
		return "", err
	}
	hash := sha256.Sum256(asn1Bytes)
	kid := base64.URLEncoding.EncodeToString(hash[:])
	return kid, nil
}

// MakeKeyFromPrivatePEM generates a Key from a PEM encoded private key.
func MakeKeyFromPrivatePEM(prvPEM string) (*Key, error) {
	block, _ := pem.Decode([]byte(prvPEM))
	if block == nil {
		return nil, fmt.Errorf("invalid pem block type")
	}
	var err error
	var prvKey *rsa.PrivateKey
	switch block.Type {
	case "PRIVATE KEY":
		// IMPORTANT: this gnarly logic is to support keys that were generated
		// with a now invalid block header.
		prvKeyIface, pkcs8Err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if pkcs8Err != nil {
			// try PKCS1 as a last ditch effort
			prvKey, err = x509.ParsePKCS1PrivateKey(block.Bytes)
			if err != nil {
				// return the original error
				return nil, pkcs8Err
			}
			// have a key, we're good
		} else {
			rsaPrvKey, ok := prvKeyIface.(*rsa.PrivateKey)
			if !ok {
				return nil, fmt.Errorf("expected PKCS8 RSA private key")
			}
			prvKey = rsaPrvKey
		}
	case "RSA PRIVATE KEY":
		prvKey, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	default:
		return nil, fmt.Errorf("unsupported pem block type [%s]", block.Type)
	}
	if err != nil {
		return nil, err
	}
	pubKey := prvKey.Public()
	if err != nil {
		return nil, err
	}
	kid, err := pubKeyToKID(pubKey)
	if err != nil {
		return nil, err
	}

	return &Key{
		PrvKey: prvKey,
		PubKey: pubKey,
		Kid:    kid,
	}, nil
}

// MakeJWKS constructs a JWKS Go object from a set of keys.
func MakeJWKS(keys []*Key) *gojwk.Key {
	if len(keys) == 0 {
		return nil
	}
	if len(keys) == 1 {
		key, err := gojwk.PublicKey(keys[0].PubKey)
		if err != nil {
			panic(err)
		}
		key.Kid = keys[0].Kid
		return key
	}
	var jwkKeys []*gojwk.Key
	for _, k := range keys {
		jwkKey, err := gojwk.PublicKey(k.PubKey)
		if err != nil {
			panic(err)
		}
		jwkKey.Kid = k.Kid
		jwkKeys = append(jwkKeys, jwkKey)
	}
	return &gojwk.Key{Keys: jwkKeys}
}
