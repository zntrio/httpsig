// Licensed to zntr.io under one or more contributor
// license agreements. See the NOTICE file distributed with
// this work for additional information regarding copyright
// ownership. zntr.io licenses this file to you under
// the Apache License, Version 2.0 (the "License"); you may
// not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.

package httpsig

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha512"
	"errors"
	"fmt"
	"net/http"
)

// NewSigner returns a signer implementation instance for `hs2019` only.
func NewSigner(krf KeyResolverFunc) Signer {
	return &signer{
		keyResolverFunc: krf,
	}
}

// -----------------------------------------------------------------------------

type signer struct {
	keyResolverFunc KeyResolverFunc
}

// Sign the given request using signature-input spec.
func (s *signer) Sign(ctx context.Context, sigMeta *SignatureInput, r *http.Request) ([]byte, error) {
	// Check arguments
	if sigMeta == nil {
		return nil, errors.New("unable to sign the request with nil signature-input")
	}
	if r == nil {
		return nil, errors.New("unable to sign nil request")
	}

	// Check expiration
	if sigMeta.IsExpired() {
		return nil, ErrExpiredSignature
	}

	// Only 'hs2019' algorithms are supported
	if sigMeta.Algorithm != AlgorithmHS2019 {
		return nil, ErrNotSupportedSignature
	}

	// Retrieve key from repository
	key, err := s.keyResolverFunc(ctx, sigMeta.KeyID)
	if err != nil && !errors.Is(err, ErrKeyNotFound) {
		return nil, fmt.Errorf("unable to retrieve key '%s': %w", sigMeta.KeyID, err)
	}
	if key == nil || errors.Is(err, ErrKeyNotFound) {
		return nil, ErrKeyNotFound
	}

	// Prepare protected body
	msg, err := protected(sigMeta, r)
	if err != nil {
		return nil, fmt.Errorf("unable to generate message: %w", err)
	}

	// Use appropriate verification according to key type
	switch k := key.(type) {
	case *rsa.PrivateKey:
		return s.signRSA(k, msg)
	case *ecdsa.PrivateKey:
		return s.signECDSA(k, msg)
	case ed25519.PrivateKey:
		return s.signEdDSA(k, msg)
	case []byte:
		return s.sealHMAC(k, msg)
	default:
	}

	// Unsupported key
	return nil, fmt.Errorf("unsupported private key type '%T'", key)
}

// -----------------------------------------------------------------------------

// signRSA uses RSASSA-PSS with SHA-512
func (s *signer) signRSA(priv *rsa.PrivateKey, protected []byte) ([]byte, error) {
	// Compute SHA-512
	h := sha512.Sum512(protected)

	// Sign the request
	sig, err := rsa.SignPSS(rand.Reader, priv, crypto.SHA512, h[:], nil)
	if err != nil {
		return nil, fmt.Errorf("unable to sign request: %w", err)
	}

	// Default to false
	return sig, nil
}

// signECDSA uses private key curve with SHA-512
func (s *signer) signECDSA(priv *ecdsa.PrivateKey, protected []byte) ([]byte, error) {
	// Compute SHA-512
	h := sha512.Sum512(protected)

	// Sign the request
	sig, err := ecdsa.SignASN1(rand.Reader, priv, h[:])
	if err != nil {
		return nil, fmt.Errorf("unable to sign request: %w", err)
	}

	// Default to false
	return sig, nil
}

// signEdDSA uses Ed25519 curve with SHA-512
func (s *signer) signEdDSA(priv ed25519.PrivateKey, protected []byte) ([]byte, error) {
	sig := ed25519.Sign(priv, protected)
	return sig, nil
}

// sealHMAC uses HMAC with SHA-512
func (s *signer) sealHMAC(secret, protected []byte) ([]byte, error) {
	// Compute HMAC-SHA-512
	hm := hmac.New(sha512.New, secret)
	hm.Write(protected)

	// Default to false
	return hm.Sum(nil), nil
}
