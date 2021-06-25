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

func Test_verifier_Verify(t *testing.T) {
	type fields struct {
		keyResolverFunc KeyResolverFunc
	}
	type args struct {
		ctx       context.Context
		sigMeta   *SignatureInput
		signature []byte
		r         *http.Request
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    bool
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
					ID:        "sig1",
					Algorithm: "",
					KeyID:     "test",
					Expires:   0,
					Created:   uint64(time.Now().Unix()),
					Headers:   []string{"@created", "@request-target"},
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
					pub, _, _ := ed25519.GenerateKey(rand.Reader)
					return pub, nil
				},
			},
			args: args{
				sigMeta: &SignatureInput{
					ID:        "sig1",
					Algorithm: AlgorithmEdDSAEd25519SHA512,
					KeyID:     "test",
					Expires:   uint64(time.Now().Unix()) + 1000,
					Created:   uint64(time.Now().Unix()),
					Headers:   []string{"@created", "@request-target", "@expires", "x-custom-header"},
				},
				signature: []byte{},
				r: func() *http.Request {
					req := httptest.NewRequest(http.MethodPost, "http://localhost:8080/api/v1/webhook?key=1", bytes.NewBufferString("{}"))
					req.Header.Set("x-custom-header", "test")
					return req
				}(),
			},
			wantErr: false,
			want:    false,
		},
		{
			name: "rsassa-pss",
			fields: fields{
				keyResolverFunc: func(ctx context.Context, kid string) (interface{}, error) {
					priv, _ := rsa.GenerateKey(rand.Reader, 2048)
					return &priv.PublicKey, nil
				},
			},
			args: args{
				sigMeta: &SignatureInput{
					ID:        "sig1",
					Algorithm: AlgorithmRSAPSSSHA512,
					KeyID:     "test",
					Expires:   0,
					Created:   uint64(time.Now().Unix()),
					Headers:   []string{"@created", "@request-target"},
				},
				signature: []byte{},
				r:         httptest.NewRequest(http.MethodPost, "http://localhost:8080/api/v1/webhook", bytes.NewBufferString("{}")),
			},
			wantErr: false,
			want:    false,
		},
		{
			name: "rsassa-pkcs",
			fields: fields{
				keyResolverFunc: func(ctx context.Context, kid string) (interface{}, error) {
					priv, _ := rsa.GenerateKey(rand.Reader, 2048)
					return &priv.PublicKey, nil
				},
			},
			args: args{
				sigMeta: &SignatureInput{
					ID:        "sig1",
					Algorithm: AlgorithmRSAV15SHA256,
					KeyID:     "test",
					Expires:   0,
					Created:   uint64(time.Now().Unix()),
					Headers:   []string{"@created", "@request-target"},
				},
				signature: []byte{},
				r:         httptest.NewRequest(http.MethodPost, "http://localhost:8080/api/v1/webhook", bytes.NewBufferString("{}")),
			},
			wantErr: false,
			want:    false,
		},
		{
			name: "ecdsa",
			fields: fields{
				keyResolverFunc: func(ctx context.Context, kid string) (interface{}, error) {
					priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
					return &priv.PublicKey, nil
				},
			},
			args: args{
				sigMeta: &SignatureInput{
					ID:        "sig1",
					Algorithm: AlgorithmECDSAP256SHA256,
					KeyID:     "test",
					Expires:   0,
					Created:   uint64(time.Now().Unix()),
					Headers:   []string{"@created", "@request-target"},
				},
				signature: []byte{},
				r:         httptest.NewRequest(http.MethodPost, "http://localhost:8080/api/v1/webhook", bytes.NewBufferString("{}")),
			},
			wantErr: false,
			want:    false,
		},
		{
			name: "hmac",
			fields: fields{
				keyResolverFunc: func(ctx context.Context, kid string) (interface{}, error) {
					secret := make([]byte, 64)
					io.ReadFull(rand.Reader, secret[:])
					return secret[:], nil
				},
			},
			args: args{
				sigMeta: &SignatureInput{
					ID:        "sig1",
					Algorithm: AlgorithmHMACSHA256,
					KeyID:     "test",
					Expires:   0,
					Created:   uint64(time.Now().Unix()),
					Headers:   []string{"@created", "@request-target"},
				},
				signature: []byte{},
				r:         httptest.NewRequest(http.MethodPost, "http://localhost:8080/api/v1/webhook", bytes.NewBufferString("{}")),
			},
			wantErr: false,
			want:    false,
		},
		{
			name: "unsupported key",
			fields: fields{
				keyResolverFunc: func(ctx context.Context, kid string) (interface{}, error) {
					return uint64(0), nil
				},
			},
			args: args{
				sigMeta: &SignatureInput{
					ID:        "sig1",
					Algorithm: AlgorithmHMACSHA256,
					KeyID:     "test",
					Expires:   0,
					Created:   uint64(time.Now().Unix()),
					Headers:   []string{"@created", "@request-target"},
				},
				signature: []byte{},
				r:         httptest.NewRequest(http.MethodPost, "http://localhost:8080/api/v1/webhook", bytes.NewBufferString("{}")),
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := &verifier{
				keyResolverFunc: tt.fields.keyResolverFunc,
			}
			got, err := v.Verify(tt.args.ctx, tt.args.sigMeta, tt.args.signature, tt.args.r)
			if (err != nil) != tt.wantErr {
				t.Errorf("verifier.Verify() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("verifier.Verify() = %v, want %v", got, tt.want)
			}
		})
	}
}
