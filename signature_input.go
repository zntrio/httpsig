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
	"fmt"
	"strings"
	"time"
)

// DefaultSignatureInput returns a default signature-inpupt for request signing.
func DefaultSignatureInput(kid string) *SignatureInput {
	return &SignatureInput{
		ID:        "sig1",
		Algorithm: AlgorithmRSAPSSSHA512,
		KeyID:     kid,
		Created:   uint64(time.Now().Unix()),
		Headers:   []string{},
		Expires:   0, // No expiration
	}
}

// -----------------------------------------------------------------------------

// SignatureInput represents signature metadata.
type SignatureInput struct {
	ID        string
	Algorithm Algorithm
	KeyID     string
	Expires   uint64
	Created   uint64
	Nonce     string
	Headers   []string
}

func (s *SignatureInput) String() string {
	return fmt.Sprintf("%s=%s", s.ID, s.Params())
}

func (s *SignatureInput) Params() string {
	res := fmt.Sprintf(
		`(%s); alg="%s"; keyid="%s"; created=%d`,
		strings.Join(s.Headers, ", "), s.Algorithm, s.KeyID, s.Created,
	)
	if s.Expires > 0 {
		res = fmt.Sprintf("%s; expires=%d", res, s.Expires)
	}
	if s.Nonce != "" {
		res = fmt.Sprintf(`%s; nonce="%s"`, res, s.Nonce)
	}

	return res
}

// IsExpired returns true if signature is expired.
func (s *SignatureInput) IsExpired() bool {
	return s.Expires > 0 && s.Expires < uint64(time.Now().Unix())
}
