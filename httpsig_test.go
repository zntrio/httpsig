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
				signature: `sig1=(*request-target *created host date cache-control x-empty-header x-example);kid="test-key-a";alg=hs2019;created=1402170695;expires=1402170995`,
			},
			want: []*SignatureInput{
				{
					ID:        "sig1",
					Headers:   []string{"*request-target", "*created", "host", "date", "cache-control", "x-empty-header", "x-example"},
					KeyID:     "test-key-a",
					Algorithm: "hs2019",
					Created:   1402170695,
					Expires:   1402170995,
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
