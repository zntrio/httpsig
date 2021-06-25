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
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func Test_signer_Sign(t *testing.T) {
	type fields struct {
		alg             Algorithm
		keyResolverFunc KeyResolverFunc
	}
	type args struct {
		ctx     context.Context
		sigMeta *SignatureInput
		r       *http.Request
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    []byte
		wantErr bool
	}{
		{
			name:    "nil",
			wantErr: true,
		},
		{
			name: "nil request",
			args: args{
				sigMeta: &SignatureInput{
					ID:      "sig1",
					KeyID:   "test",
					Expires: 0,
					Created: uint64(time.Now().Unix()),
					Headers: []string{"@created", "@request-target"},
				},
			},
			wantErr: true,
		},
		{
			name: "sigInput expired",
			args: args{
				sigMeta: &SignatureInput{
					ID:      "sig1",
					KeyID:   "test",
					Expires: 1,
					Created: uint64(time.Now().Unix()),
					Headers: []string{"@created", "@request-target"},
				},
				r: httptest.NewRequest(http.MethodPost, "http://localhost:8080/api/v1/webhook", bytes.NewBufferString("{}")),
			},
			wantErr: true,
		},
		{
			name: "invalid algorithm",
			args: args{
				sigMeta: &SignatureInput{
					ID:      "sig1",
					KeyID:   "test",
					Expires: 0,
					Created: uint64(time.Now().Unix()),
					Headers: []string{"@created", "@request-target"},
				},
				r: httptest.NewRequest(http.MethodPost, "http://localhost:8080/api/v1/webhook", bytes.NewBufferString("{}")),
			},
			wantErr: true,
		},
		{
			name: "kid not found",
			fields: fields{
				keyResolverFunc: func(ctx context.Context, kid string) (interface{}, error) {
					return nil, ErrKeyNotFound
				},
				alg: AlgorithmRSAPSSSHA512,
			},
			args: args{
				sigMeta: &SignatureInput{
					ID:      "sig1",
					KeyID:   "test",
					Expires: 0,
					Created: uint64(time.Now().Unix()),
					Headers: []string{"@created", "@request-target"},
				},
				r: httptest.NewRequest(http.MethodPost, "http://localhost:8080/api/v1/webhook", bytes.NewBufferString("{}")),
			},
			wantErr: true,
		},
		{
			name: "kid resolver error",
			fields: fields{
				keyResolverFunc: func(ctx context.Context, kid string) (interface{}, error) {
					return nil, fmt.Errorf("test")
				},
				alg: AlgorithmRSAPSSSHA512,
			},
			args: args{
				sigMeta: &SignatureInput{
					ID:      "sig1",
					KeyID:   "test",
					Expires: 0,
					Created: uint64(time.Now().Unix()),
					Headers: []string{"@created", "@request-target"},
				},
				r: httptest.NewRequest(http.MethodPost, "http://localhost:8080/api/v1/webhook", bytes.NewBufferString("{}")),
			},
			wantErr: true,
		},
		{
			name: "header not found",
			fields: fields{
				keyResolverFunc: func(ctx context.Context, kid string) (interface{}, error) {
					pub, _, _ := ed25519.GenerateKey(rand.Reader)
					return pub, nil
				},
				alg: AlgorithmRSAPSSSHA512,
			},
			args: args{
				sigMeta: &SignatureInput{
					ID:      "sig1",
					KeyID:   "test",
					Expires: 0,
					Created: uint64(time.Now().Unix()),
					Headers: []string{"@created", "@request-target", "x-not-exist"},
				},
				r: httptest.NewRequest(http.MethodPost, "http://localhost:8080/api/v1/webhook", bytes.NewBufferString("{}")),
			},
			wantErr: true,
		},
		{
			name: "ed25519",
			fields: fields{
				keyResolverFunc: func(ctx context.Context, kid string) (interface{}, error) {
					_, priv, _ := ed25519.GenerateKey(rand.Reader)
					return priv, nil
				},
				alg: AlgorithmEdDSAEd25519BLAKE2B512,
			},
			args: args{
				sigMeta: &SignatureInput{
					ID:      "sig1",
					KeyID:   "test",
					Expires: uint64(time.Now().Unix()) + 1000,
					Created: uint64(time.Now().Unix()),
					Headers: []string{"@created", "@request-target", "@expires", "x-custom-header"},
				},
				r: func() *http.Request {
					req := httptest.NewRequest(http.MethodPost, "http://localhost:8080/api/v1/webhook?key=1", bytes.NewBufferString("{}"))
					req.Header.Set("x-custom-header", "test")
					return req
				}(),
			},
			wantErr: false,
		},
		{
			name: "rsassa-pss",
			fields: fields{
				keyResolverFunc: func(ctx context.Context, kid string) (interface{}, error) {
					priv, _ := rsa.GenerateKey(rand.Reader, 2048)
					return priv, nil
				},
				alg: AlgorithmRSAPSSSHA512,
			},
			args: args{
				sigMeta: &SignatureInput{
					ID:      "sig1",
					KeyID:   "test",
					Expires: 0,
					Created: uint64(time.Now().Unix()),
					Headers: []string{"@created", "@request-target"},
				},
				r: httptest.NewRequest(http.MethodPost, "http://localhost:8080/api/v1/webhook", bytes.NewBufferString("{}")),
			},
			wantErr: false,
		},
		{
			name: "rsassa-pkcs",
			fields: fields{
				keyResolverFunc: func(ctx context.Context, kid string) (interface{}, error) {
					priv, _ := rsa.GenerateKey(rand.Reader, 2048)
					return priv, nil
				},
				alg: AlgorithmRSAV15SHA256,
			},
			args: args{
				sigMeta: &SignatureInput{
					ID:      "sig1",
					KeyID:   "test",
					Expires: 0,
					Created: uint64(time.Now().Unix()),
					Headers: []string{"@created", "@request-target"},
				},
				r: httptest.NewRequest(http.MethodPost, "http://localhost:8080/api/v1/webhook", bytes.NewBufferString("{}")),
			},
			wantErr: false,
		},
		{
			name: "ecdsa",
			fields: fields{
				keyResolverFunc: func(ctx context.Context, kid string) (interface{}, error) {
					priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
					return priv, nil
				},
				alg: AlgorithmECDSAP256SHA256,
			},
			args: args{
				sigMeta: &SignatureInput{
					ID:      "sig1",
					KeyID:   "test",
					Expires: 0,
					Created: uint64(time.Now().Unix()),
					Headers: []string{"@created", "@request-target"},
				},
				r: httptest.NewRequest(http.MethodPost, "http://localhost:8080/api/v1/webhook", bytes.NewBufferString("{}")),
			},
			wantErr: false,
		},
		{
			name: "hmac",
			fields: fields{
				keyResolverFunc: func(ctx context.Context, kid string) (interface{}, error) {
					secret := make([]byte, 64)
					io.ReadFull(rand.Reader, secret[:])
					return secret[:], nil
				},
				alg: AlgorithmHMACSHA256,
			},
			args: args{
				sigMeta: &SignatureInput{
					ID:      "sig1",
					KeyID:   "test",
					Expires: 0,
					Created: uint64(time.Now().Unix()),
					Headers: []string{"@created", "@request-target"},
				},
				r: httptest.NewRequest(http.MethodPost, "http://localhost:8080/api/v1/webhook", bytes.NewBufferString("{}")),
			},
			wantErr: false,
		},
		{
			name: "unsupported key",
			fields: fields{
				keyResolverFunc: func(ctx context.Context, kid string) (interface{}, error) {
					return uint64(0), nil
				},
				alg: AlgorithmECDSAP256SHA256,
			},
			args: args{
				sigMeta: &SignatureInput{
					ID:      "sig1",
					KeyID:   "test",
					Expires: 0,
					Created: uint64(time.Now().Unix()),
					Headers: []string{"@created", "@request-target"},
				},
				r: httptest.NewRequest(http.MethodPost, "http://localhost:8080/api/v1/webhook", bytes.NewBufferString("{}")),
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &signer{
				alg:             tt.fields.alg,
				keyResolverFunc: tt.fields.keyResolverFunc,
			}
			_, err := s.Sign(tt.args.ctx, tt.args.sigMeta, tt.args.r)
			if (err != nil) != tt.wantErr {
				t.Errorf("signer.Sign() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}
