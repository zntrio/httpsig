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

	"github.com/ucarion/sfv"
)

type sfvSigInput struct {
	Headers   []string
	Created   uint64 `sfv:"created"`
	Expires   uint64 `sfv:"expires"`
	Algorithm string `sfv:"alg"`
	KeyID     string `sfv:"keyid"`
	Nonce     string `sfv:"nonce"`
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
			Algorithm: Algorithm(meta.Algorithm),
			Created:   meta.Created,
			Expires:   meta.Expires,
			KeyID:     meta.KeyID,
			Headers:   []string{},
			Nonce:     meta.Nonce,
		}

		// Filter not supported algorithm
		switch sig.Algorithm {
		case AlgorithmRSAPSSSHA512:
		case AlgorithmRSAV15SHA256:
		case AlgorithmHMACSHA256:
		case AlgorithmECDSAP256SHA256:
		case AlgorithmEdDSAEd25519SHA512:
		default:
			// Skip invalid signature algorithm
			continue
		}

		// Extract headers
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
		RWMutex: sync.RWMutex{},
		sigs:    sigMap,
	}, nil
}

// -----------------------------------------------------------------------------

// SignatureSet represents a dictionary of signature-input reference and
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
	res := make([]string, len(set.sigs))
	i := 0
	for k, v := range set.sigs {
		data, err := sfv.Marshal(v)
		if err != nil {
			panic(err)
		}
		res[i] = fmt.Sprintf("%s=%s", k, data)
		i++
	}

	return strings.Join(res, ", ")
}
