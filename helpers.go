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
	"fmt"
	"net/http"
	"strings"
)

func protected(sigMeta *SignatureInput, r *http.Request) ([]byte, error) {
	// Prepare protected body
	var protected bytes.Buffer
	for _, h := range sigMeta.Headers {
		switch h {
		case "*created":
			fmt.Fprintf(&protected, "*created: %d\n", sigMeta.Created)
		case "*expires":
			fmt.Fprintf(&protected, "*expires: %d\n", sigMeta.Expires)
		case "*request-target":
			fmt.Fprintf(&protected, "*request-target: %s\n", requestTarget(r))
		case "host":
			fmt.Fprintf(&protected, "host: %s\n", r.Host)
		default:
			if val := r.Header.Get(h); val != "" {
				fmt.Fprintf(&protected, "%s: %s\n", strings.ToLower(h), r.Header.Get(h))
			} else {
				return nil, fmt.Errorf("request does not contains '%s' header", h)
			}
		}
	}

	// No error
	return protected.Bytes(), nil
}

func requestTarget(r *http.Request) string {
	rt := fmt.Sprintf("%s %s", strings.ToLower(r.Method), r.URL.Path)
	if r.URL.RawQuery != "" {
		rt = fmt.Sprintf("%s?%s", rt, r.URL.RawQuery)
	}

	return rt
}
