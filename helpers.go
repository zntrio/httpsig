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
	"bytes"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/ucarion/sfv"
)

func protected(sigMeta *SignatureInput, r *http.Request) ([]byte, error) {
	// Check arguments
	if sigMeta == nil {
		return nil, errors.New("unable to generate protected content with nil signature-input")
	}
	if r == nil {
		return nil, errors.New("unable to generate protected content with nil request")
	}

	// Clean headers
	canonicalHeaders := map[string]string{}
	canonicalHeaders["@request-target"] = requestTarget(r)
	canonicalHeaders["@created"] = fmt.Sprintf("%d", sigMeta.Created)
	if sigMeta.Expires > 0 {
		canonicalHeaders["@expires"] = fmt.Sprintf("%d", sigMeta.Expires)
	}
	canonicalHeaders["host"] = r.Host

	// https://www.ietf.org/id/draft-ietf-httpbis-message-signatures-05.html#name-http-header-fields
	for key, values := range r.Header {
		var hdrs []string
		for _, v := range values {
			hdrs = append(hdrs, strings.TrimSpace(v))
		}
		canonicalHeaders[strings.ToLower(key)] = strings.Join(hdrs, ", ")
	}

	// Prepare protected body
	var protected bytes.Buffer
	for _, h := range sigMeta.Headers {
		if err := canonicalExtract(h, canonicalHeaders, &protected); err != nil {
			return nil, fmt.Errorf("unable to extract '%s' header: %w", h, err)
		}
	}

	// Append signature params
	fmt.Fprintf(&protected, "@signature-params: %s\n", sigMeta.Params())

	// No error
	return protected.Bytes(), nil
}

func canonicalExtract(key string, canonicalHeaders map[string]string, protected *bytes.Buffer) error {
	// Check if value contains a colon character
	if strings.Contains(key, ":") {
		// Split value
		parts := strings.SplitN(key, ":", 2)
		if len(parts) != 2 {
			return fmt.Errorf("invalid header reference '%s'", key)
		}

		// Check if prefix value is an existing header
		prefix := parts[0]
		hValue, ok := canonicalHeaders[prefix]
		if !ok {
			return fmt.Errorf("header '%s' not found", prefix)
		}

		// Suffix is integer => list
		if idx, errConv := strconv.Atoi(parts[1]); errConv == nil && idx >= 0 {
			// Deserialize as List
			var list sfv.List
			if err := sfv.Unmarshal(hValue, &list); err != nil {
				return fmt.Errorf("unable to decode '%s' value as a list: %w", prefix, err)
			}

			// Check size match
			if idx > len(list) {
				return fmt.Errorf("invalid list index '%d' for '%s'", idx, prefix)
			}

			// Marshal dictionary
			member, errMarshal := sfv.Marshal(list[:idx])
			if errMarshal != nil {
				return fmt.Errorf("unable to marshal item '%s': %w", key, errMarshal)
			}

			fmt.Fprintf(protected, "%s: %s\n", strings.ToLower(prefix), member)
		} else {
			// Deserialize as Map
			var dict sfv.Dictionary
			if errUnmarshal := sfv.Unmarshal(hValue, &dict); errUnmarshal != nil {
				return fmt.Errorf("unable to decode '%s' value as a dictionary: %w", prefix, errUnmarshal)
			}

			// Retrieve list member
			value, ok := dict.Map[parts[1]]
			if !ok {
				return fmt.Errorf("invalid dictionary key '%s' for '%s'", parts[1], prefix)
			}

			// Marshal dictionary
			member, errMarshal := sfv.Marshal(sfv.Dictionary{
				Keys: []string{
					strings.ToLower(parts[1]),
				},
				Map: map[string]sfv.Member{
					strings.ToLower(parts[1]): value,
				},
			})
			if errMarshal != nil {
				return fmt.Errorf("unable to marshal item '%s': %w", key, errMarshal)
			}

			fmt.Fprintf(protected, "%s: %s\n", strings.ToLower(prefix), member)
		}
	} else {
		hValue, ok := canonicalHeaders[key]
		if !ok {
			return fmt.Errorf("header '%s' not found", key)
		}

		fmt.Fprintf(protected, "%s: %s\n", strings.ToLower(key), hValue)
	}

	return nil
}

func requestTarget(r *http.Request) string {
	rt := fmt.Sprintf("%s %s", strings.ToLower(r.Method), r.URL.Path)
	if r.URL.RawQuery != "" {
		rt = fmt.Sprintf("%s?%s", rt, r.URL.RawQuery)
	}

	return rt
}
