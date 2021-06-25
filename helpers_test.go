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
	"bufio"
	"bytes"
	"net/http"
	"reflect"
	"testing"
)

func sampleRequest() *http.Request {
	r, err := http.ReadRequest(bufio.NewReader(bytes.NewBufferString(`POST /foo?param=value&pet=dog HTTP/1.1
Host: example.com
Date: Tue, 07 Jun 2014 20:51:35 GMT
Content-Type: application/json
X-Custom: 1
X-Custom: 2
X-Dictionary: a=1, b=2;x=1;y=2, c=(a b c)
X-List-A: a, b, c, d, e, f
X-List-B:
Digest: SHA-256=X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=
Content-Length: 18
Signature-Input: sig1=(*request-target, *created, host, date,
    cache-control, x-empty-header, x-example); kid="test-key-a";
    alg=rsa-pss-sha512; created=1402170695; expires=1402170995
Signature: sig1=:K2qGT5srn2OGbOIDzQ6kYT+ruaycnDAAUpKv+ePFfD0RAxn/1BUe
    Zx/Kdrq32DrfakQ6bPsvB9aqZqognNT6be4olHROIkeV879RrsrObury8L9SCEibe
    oHyqU/yCjphSmEdd7WD+zrchK57quskKwRefy2iEC5S2uAH0EPyOZKWlvbKmKu5q4
    CaB8X/I5/+HLZLGvDiezqi6/7p2Gngf5hwZ0lSdy39vyNMaaAT0tKo6nuVw0S1MVg
    1Q7MpWYZs0soHjttq0uLIA3DIbQfLiIvK6/l0BdWTU7+2uQj7lBkQAsFZHoA96ZZg
    FquQrXRlmYOh+Hx5D9fJkXcXe5tmAg==:
X-Forwarded-For: 192.0.2.123
Signature-Input: reverse_proxy_sig=(*created, host, date,
    signature:sig1, x-forwarded-for); kid="test-key-a";
    alg=rsa-pss-sha512; created=1402170695; expires=1402170695.25
Signature: reverse_proxy_sig=:ON3HsnvuoTlX41xfcGWaOEVo1M3bJDRBOp0Pc/O
    jAOWKQn0VMY0SvMMWXS7xG+xYVa152rRVAo6nMV7FS3rv0rR5MzXL8FCQ2A35DCEN
    LOhEgj/S1IstEAEFsKmE9Bs7McBsCtJwQ3hMqdtFenkDffSoHOZOInkTYGafkoy78
    l1VZvmb3Y4yf7McJwAvk2R3gwKRWiiRCw448Nt7JTWzhvEwbh7bN2swc/v3NJbg/w
    JYyYVbelZx4IywuZnYFxgPl/qvqbAjeEVvaLKLgSMr11y+uzxCHoMnDUnTYhMrmOT
    4O8lBLfRFOcoJPKBdoKg9U0a96U2mUug1bFOozEVYFg==:

{"hello": "world"}`)))
	if err != nil {
		panic(err)
	}

	return r
}

func Test_protected(t *testing.T) {
	type args struct {
		sigMeta *SignatureInput
		r       *http.Request
	}
	tests := []struct {
		name    string
		args    args
		want    string
		wantErr bool
	}{
		{
			name:    "nil",
			wantErr: true,
		},
		{
			name: "nil request",
			args: args{
				sigMeta: DefaultSignatureInput("test"),
			},
			wantErr: true,
		},
		{
			name: "valid",
			args: args{
				sigMeta: &SignatureInput{
					ID:        "sig1",
					Headers:   []string{"@request-target", "@created", "@expires", "host", "date"},
					KeyID:     "test-key-a",
					Algorithm: "rsa-pss-sha512",
					Created:   1402170695,
					Expires:   1402170995,
					Nonce:     "1234567890",
				},
				r: sampleRequest(),
			},
			wantErr: false,
			want: "@request-target: post /foo?param=value&pet=dog\n" +
				"@created: 1402170695\n" +
				"@expires: 1402170995\n" +
				"host: example.com\n" +
				"date: Tue, 07 Jun 2014 20:51:35 GMT\n" +
				`@signature-params: (@request-target, @created, @expires, host, date); alg="rsa-pss-sha512"; keyid="test-key-a"; created=1402170695; expires=1402170995; nonce="1234567890"` + "\n",
		},
		{
			name: "valid - no header",
			args: args{
				sigMeta: &SignatureInput{
					ID:        "sig1",
					Headers:   []string{},
					KeyID:     "test-key-a",
					Algorithm: "rsa-pss-sha512",
					Created:   1402170695,
					Expires:   1402170995,
					Nonce:     "1234567890",
				},
				r: sampleRequest(),
			},
			wantErr: false,
			want:    `@signature-params: (); alg="rsa-pss-sha512"; keyid="test-key-a"; created=1402170695; expires=1402170995; nonce="1234567890"` + "\n",
		},
		{
			name: "valid - double header",
			args: args{
				sigMeta: &SignatureInput{
					ID:        "sig1",
					Headers:   []string{"@request-target", "@created", "@expires", "host", "date", "x-custom"},
					KeyID:     "test-key-a",
					Algorithm: "rsa-pss-sha512",
					Created:   1402170695,
					Expires:   1402170995,
					Nonce:     "1234567890",
				},
				r: sampleRequest(),
			},
			wantErr: false,
			want: "@request-target: post /foo?param=value&pet=dog\n" +
				"@created: 1402170695\n" +
				"@expires: 1402170995\n" +
				"host: example.com\n" +
				"date: Tue, 07 Jun 2014 20:51:35 GMT\n" +
				"x-custom: 1, 2\n" +
				`@signature-params: (@request-target, @created, @expires, host, date, x-custom); alg="rsa-pss-sha512"; keyid="test-key-a"; created=1402170695; expires=1402170995; nonce="1234567890"` + "\n",
		},
		{
			name: "valid - dictionary prefix",
			args: args{
				sigMeta: &SignatureInput{
					ID:        "sig1",
					Headers:   []string{"@request-target", "@created", "x-dictionary:a", "x-dictionary:b", "x-dictionary:c"},
					KeyID:     "test-key-a",
					Algorithm: "rsa-pss-sha512",
					Created:   1402170695,
					Expires:   1402170995,
					Nonce:     "1234567890",
				},
				r: sampleRequest(),
			},
			wantErr: false,
			want: "@request-target: post /foo?param=value&pet=dog\n" +
				"@created: 1402170695\n" +
				"x-dictionary: a=1\n" +
				"x-dictionary: b=2;x=1;y=2\n" +
				"x-dictionary: c=(a b c)\n" +
				`@signature-params: (@request-target, @created, x-dictionary:a, x-dictionary:b, x-dictionary:c); alg="rsa-pss-sha512"; keyid="test-key-a"; created=1402170695; expires=1402170995; nonce="1234567890"` + "\n",
		},
		{
			name: "valid - list prefix",
			args: args{
				sigMeta: &SignatureInput{
					ID:        "sig1",
					Headers:   []string{"@request-target", "@created", "x-list-a:0", "x-list-a:2"},
					KeyID:     "test-key-a",
					Algorithm: "rsa-pss-sha512",
					Created:   1402170695,
					Expires:   1402170995,
					Nonce:     "1234567890",
				},
				r: sampleRequest(),
			},
			wantErr: false,
			want: "@request-target: post /foo?param=value&pet=dog\n" +
				"@created: 1402170695\n" +
				"x-list-a: \n" +
				"x-list-a: a, b\n" +
				`@signature-params: (@request-target, @created, x-list-a:0, x-list-a:2); alg="rsa-pss-sha512"; keyid="test-key-a"; created=1402170695; expires=1402170995; nonce="1234567890"` + "\n",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := protected(tt.args.sigMeta, tt.args.r)
			if (err != nil) != tt.wantErr {
				t.Errorf("protected() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(string(got), tt.want) {
				t.Errorf("protected() = %s, want %v", got, tt.want)
			}
		})
	}
}
