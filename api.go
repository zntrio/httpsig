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
	"errors"
	"net/http"
)

// Algorithm describes supported signing suite supported.
type Algorithm string

const (
	// AlgorithmRSAPSSSHA512 represents signature algorithm RSASSA-PSS using SHA-512
	AlgorithmRSAPSSSHA512 Algorithm = "rsa-pss-sha512"
	// AlgorithmRSAV15SHA256 represents signature algorithm RSASSA-PKCS1-v1_5 using SHA-256
	AlgorithmRSAV15SHA256 Algorithm = "rsa-v1_5-sha256"
	// AlgorithmRSAV15SHA256 represents signature algorithm HMAC using SHA-256
	AlgorithmHMACSHA256 Algorithm = "hmac-sha256"
	// AlgorithmECDSAP256SHA256 represents signature algorithm using ECDA P-256 curve with SHA-256
	AlgorithmECDSAP256SHA256 Algorithm = "ecdsa-p256-sha256"
	// AlgorithmEdDSAEd25519BLAKE512 represents signature algorithm using EdDSA Ed25519 curve with BLAKE2B-512
	AlgorithmEdDSAEd25519BLAKE2B512 Algorithm = "eddsa-ed25519-blake2b512"
)

// Verifier describes signature verification implementation contract.
type Verifier interface {
	Verify(ctx context.Context, sigMeta *SignatureInput, signature []byte, r *http.Request) (bool, error)
}

// Signer describes signature signature implementation contract.
type Signer interface {
	Sign(ctx context.Context, sigMeta *SignatureInput, r *http.Request) ([]byte, error)
}

var (
	// ErrKeyNotFound is raised when KeyResolverFunc desn't find the requested key.
	ErrKeyNotFound = errors.New("key not found")
	// ErrExpiredSignature is raised when trying to operate using an expired
	// signature input.
	ErrExpiredSignature = errors.New("expired signature")
	// ErrNotSupportedSignature is raised when KeyResolverFunc returned an
	// invalid key type for operation.
	ErrNotSupportedSignature = errors.New("not supported signature")
)

// KeyResolverFunc is used to resolve crypto material from key identifier.
type KeyResolverFunc func(ctx context.Context, kid string) (interface{}, error)
