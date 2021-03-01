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
	"crypto/rsa"
	"crypto/sha512"
	"crypto/subtle"
	"errors"
	"fmt"
	"net/http"
)

// NewVerifier returns a verifier implementation instance for `hs2019` only.
func NewVerifier(krf KeyResolverFunc) Verifier {
	return &verifier{
		keyResolverFunc: krf,
	}
}

// -----------------------------------------------------------------------------

type verifier struct {
	keyResolverFunc KeyResolverFunc
}

// Verify request with current signature.
//nolint:cyclop // Refactor
func (v *verifier) Verify(ctx context.Context, sigMeta *SignatureInput, signature []byte, r *http.Request) (bool, error) {
	// Check arguments
	if sigMeta == nil {
		return false, errors.New("unable to verify request with nil signature input")
	}
	if r == nil {
		return false, errors.New("unable to verify nil request")
	}

	// Check if current signature is expired
	if sigMeta.IsExpired() {
		return false, ErrExpiredSignature
	}

	// Only 'hs2019' algorithms are supported
	if sigMeta.Algorithm != AlgorithmHS2019 {
		return false, ErrNotSupportedSignature
	}

	// Retrieve key from repository
	key, err := v.keyResolverFunc(ctx, sigMeta.KeyID)
	if err != nil && !errors.Is(err, ErrKeyNotFound) {
		return false, fmt.Errorf("unable to retrieve key '%s': %w", sigMeta.KeyID, err)
	}
	if key == nil || errors.Is(err, ErrKeyNotFound) {
		return false, ErrKeyNotFound
	}

	// Prepare protected body
	msg, err := protected(sigMeta, r)
	if err != nil {
		return false, fmt.Errorf("unable to generate message: %w", err)
	}

	// Use appropriate verification according to key type
	switch k := key.(type) {
	case *rsa.PublicKey:
		return v.verifyRSA(k, msg, signature)
	case *ecdsa.PublicKey:
		return v.verifyECDSA(k, msg, signature)
	case ed25519.PublicKey:
		return v.verifyEdDSA(k, msg, signature)
	case []byte:
		return v.verifyHMAC(k, msg, signature)
	default:
	}

	// Unsupported key
	return false, fmt.Errorf("unsupported public key type '%T'", key)
}

// -----------------------------------------------------------------------------

// verifyRSA uses RSASSA-PSS with SHA-512
func (v *verifier) verifyRSA(pub *rsa.PublicKey, protected, signature []byte) (bool, error) {
	// Compute SHA-512
	h := sha512.Sum512(protected)

	// Verify signature
	err := rsa.VerifyPSS(pub, crypto.SHA512, h[:], signature, nil)
	if err != nil {
		if errors.Is(err, rsa.ErrVerification) {
			return false, nil
		}

		return false, fmt.Errorf("unable to verify RSASSA-PSS signature: %w", err)
	}

	// Default to false
	return true, nil
}

// verifyECDSA uses public key curve with SHA-512
func (v *verifier) verifyECDSA(pub *ecdsa.PublicKey, protected, signature []byte) (bool, error) {
	// Compute SHA-512
	h := sha512.Sum512(protected)

	// Verify signature
	if ecdsa.VerifyASN1(pub, h[:], signature) {
		return true, nil
	}

	// Default to false
	return false, nil
}

// verifyEdDSA uses Ed25519 curve with SHA-512
func (v *verifier) verifyEdDSA(pub ed25519.PublicKey, protected, signature []byte) (bool, error) {
	valid := ed25519.Verify(pub, protected, signature)

	return valid, nil
}

// verifyHMAC uses HMAC with SHA-512
func (v *verifier) verifyHMAC(secret, protected, signature []byte) (bool, error) {
	// Compute HMAC-SHA-512
	hm := hmac.New(sha512.New, secret)
	if _, err := hm.Write(protected); err != nil {
		return false, fmt.Errorf("unable to write payload for hmac: %w", err)
	}

	// Compare result
	if subtle.ConstantTimeCompare(hm.Sum(nil), signature) == 1 {
		return true, nil
	}

	// Default to false
	return false, nil
}
