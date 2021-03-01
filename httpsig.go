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
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/ucarion/sfv"
)

type sfvSigInput struct {
	Headers   []string
	Created   uint64 `sfv:"created"`
	Expires   uint64 `sfv:"expires"`
	Algorithm string `sfv:"alg"`
	KeyID     string `sfv:"kid"`
}

// ParseSignatureInput returns the SignatureInput descriptor.
func ParseSignatureInput(input string) ([]*SignatureInput, error) {
	if input == "" {
		return nil, errors.New("invalid signature input")
	}

	var sigInputMap map[string]sfvSigInput
	if err := sfv.Unmarshal(input, &sigInputMap); err != nil {
		return nil, fmt.Errorf("unable to unmarshal signature-input map: %w", err)
	}

	sigList := []*SignatureInput{}
	for id, meta := range sigInputMap {
		sig := &SignatureInput{
			ID:        id,
			Created:   meta.Created,
			Expires:   meta.Expires,
			KeyID:     meta.KeyID,
			Algorithm: Algorithm(meta.Algorithm),
		}

		// Extract headers
		sig.Headers = []string{}
		for _, h := range meta.Headers {
			sig.Headers = append(sig.Headers, strings.ToLower(strings.TrimSpace(h)))
		}

		sigList = append(sigList, sig)
	}

	// No error
	return sigList, nil
}

// ParseSignatureSet returns the signature map from given input.
func ParseSignatureSet(input string) (*SignatureSet, error) {
	if input == "" {
		return nil, errors.New("invalid signature input")
	}

	var sigMap map[string][]byte
	if err := sfv.Unmarshal(input, &sigMap); err != nil {
		return nil, fmt.Errorf("unable to unmarshal signature map: %w", err)
	}

	// No error
	return &SignatureSet{
		sigs: sigMap,
	}, nil
}

// -----------------------------------------------------------------------------

// SignatureInput represents signature metadata.
type SignatureInput struct {
	ID        string
	Algorithm Algorithm
	KeyID     string
	Expires   uint64
	Created   uint64
	Headers   []string
}

func (s *SignatureInput) String() string {
	res := fmt.Sprintf(
		`%s=(%s); alg="%s"; kid="%s"; created=%d`,
		s.ID, strings.Join(s.Headers, ", "), s.Algorithm, s.KeyID, s.Created,
	)
	if s.Expires > 0 {
		res = fmt.Sprintf("%s; expires=%d", res, s.Expires)
	}
	return res
}

// IsExpired returns true if signature is expired.
func (s *SignatureInput) IsExpired() bool {
	return s.Expires > 0 && s.Expires < uint64(time.Now().Unix())
}

// -----------------------------------------------------------------------------

// SignatureSet represents a dictionnary of signature-input reference and
// signature payload.
type SignatureSet struct {
	sync.RWMutex
	sigs map[string][]byte
}

// Add a signature to current set.
func (set *SignatureSet) Add(name string, sig []byte) {
	set.Lock()
	defer set.Unlock()
	if set.sigs == nil {
		set.sigs = map[string][]byte{}
	}
	set.sigs[name] = sig
}

// Get a signature by handle.
func (set *SignatureSet) Get(name string) ([]byte, bool) {
	set.RLock()
	defer set.RUnlock()
	if set.sigs == nil {
		return nil, false
	}
	sig, ok := set.sigs[name]
	return sig, ok
}

// Keys returns the list of available signatures.
func (set *SignatureSet) Keys() []string {
	set.RLock()
	defer set.RUnlock()
	res := []string{}
	for k := range set.sigs {
		res = append(res, k)
	}
	return res
}

func (set *SignatureSet) String() string {
	out, err := sfv.Marshal(set.sigs)
	if err != nil {
		panic(err)
	}
	return out
}
