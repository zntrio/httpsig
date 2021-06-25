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
	"reflect"
	"testing"
)

func TestParse(t *testing.T) {
	type args struct {
		signature string
	}
	tests := []struct {
		name    string
		args    args
		want    []*SignatureInput
		wantErr bool
	}{
		{
			name: "blank",
			args: args{
				signature: "",
			},
			wantErr: true,
		},
		{
			name: "valid",
			args: args{
				signature: `sig1=();created=1618884475;keyid="test-key-rsa-pss";alg="rsa-pss-sha512"`,
			},
			want: []*SignatureInput{
				{
					ID:        "sig1",
					Headers:   []string{},
					KeyID:     "test-key-rsa-pss",
					Algorithm: "rsa-pss-sha512",
					Created:   1618884475,
				},
			},
			wantErr: false,
		},
		{
			name: "valid with headers",
			args: args{
				signature: `sig1=("@request-target" "host" "date" "content-type" "digest" "content-length");created=1618884475;keyid="test-key-rsa-pss";alg="rsa-pss-sha512";expires=1618884495;nonce="fpxObpaLKpEdHRErAMmaeEURhibYFdBMvuExQWpMlScKnvQeNGEMXaWEvYDwEWgQ"`,
			},
			want: []*SignatureInput{
				{
					ID:        "sig1",
					Headers:   []string{"@request-target", "host", "date", "content-type", "digest", "content-length"},
					KeyID:     "test-key-rsa-pss",
					Algorithm: "rsa-pss-sha512",
					Created:   1618884475,
					Expires:   1618884495,
					Nonce:     "fpxObpaLKpEdHRErAMmaeEURhibYFdBMvuExQWpMlScKnvQeNGEMXaWEvYDwEWgQ",
				},
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseSignatureInput(tt.args.signature)
			if (err != nil) != tt.wantErr {
				t.Errorf("Parse() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Parse() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestParseSignatures(t *testing.T) {
	type args struct {
		input string
	}
	tests := []struct {
		name    string
		args    args
		want    map[string]string
		wantErr bool
	}{
		{
			name:    "empty",
			wantErr: true,
		},
		{
			name: "one sig",
			args: args{
				input: "sig1=:K2qGT5srn2OGbOIDzQ6kYT+ruaycnDAAUpKv+ePFfD0RAxn/1BUeZx/Kdrq32DrfakQ6bPsvB9aqZqognNT6be4olHROIkeV879RrsrObury8L9SCEibeoHyqU/yCjphSmEdd7WD+zrchK57quskKwRefy2iEC5S2uAH0EPyOZKWlvbKmKu5q4CaB8X/I5/+HLZLGvDiezqi6/7p2Gngf5hwZ0lSdy39vyNMaaAT0tKo6nuVw0S1MVg1Q7MpWYZs0soHjttq0uLIA3DIbQfLiIvK6/l0BdWTU7+2uQj7lBkQAsFZHoA96ZZgFquQrXRlmYOh+Hx5D9fJkXcXe5tmAg==:",
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParseSignatureSet(tt.args.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseSignatures() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}
