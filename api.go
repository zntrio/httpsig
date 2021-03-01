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
	// AlgorithmHS2019 represents signing suite (RSASSA-PSS/SHA512, ECDSA/SHA512, EdDSA/SHA512, HMAC-SHA512)
	AlgorithmHS2019 Algorithm = "hs2019"
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
