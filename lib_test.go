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

package httpsig_test

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"net/http"
	"testing"

	"zntr.io/httpsig"
)

// Imported from spec.
// https://www.ietf.org/id/draft-ietf-httpbis-message-signatures-01.html#name-example-key-rsa-test

var testRSAPublicKey = publicKeyDecode([]byte(`-----BEGIN RSA PUBLIC KEY-----
MIIBCgKCAQEAhAKYdtoeoy8zcAcR874L8cnZxKzAGwd7v36APp7Pv6Q2jdsPBRrw
WEBnez6d0UDKDwGbc6nxfEXAy5mbhgajzrw3MOEt8uA5txSKobBpKDeBLOsdJKFq
MGmXCQvEG7YemcxDTRPxAleIAgYYRjTSd/QBwVW9OwNFhekro3RtlinV0a75jfZg
kne/YiktSvLG34lw2zqXBDTC5NHROUqGTlML4PlNZS5Ri2U4aCNx2rUPRcKIlE0P
uKxI4T+HIaFpv8+rdV6eUgOrB2xeI1dSFFn/nnv5OoZJEIB+VmuKn3DCUcCZSFlQ
PSXSfBDiUGhwOw76WuSSsf1D4b/vLoJ10wIDAQAB
-----END RSA PUBLIC KEY-----`))

var testRSAPrivateKey = privateKeyDecode([]byte(`-----BEGIN RSA PRIVATE KEY-----
MIIEqAIBAAKCAQEAhAKYdtoeoy8zcAcR874L8cnZxKzAGwd7v36APp7Pv6Q2jdsP
BRrwWEBnez6d0UDKDwGbc6nxfEXAy5mbhgajzrw3MOEt8uA5txSKobBpKDeBLOsd
JKFqMGmXCQvEG7YemcxDTRPxAleIAgYYRjTSd/QBwVW9OwNFhekro3RtlinV0a75
jfZgkne/YiktSvLG34lw2zqXBDTC5NHROUqGTlML4PlNZS5Ri2U4aCNx2rUPRcKI
lE0PuKxI4T+HIaFpv8+rdV6eUgOrB2xeI1dSFFn/nnv5OoZJEIB+VmuKn3DCUcCZ
SFlQPSXSfBDiUGhwOw76WuSSsf1D4b/vLoJ10wIDAQABAoIBAG/JZuSWdoVHbi56
vjgCgkjg3lkO1KrO3nrdm6nrgA9P9qaPjxuKoWaKO1cBQlE1pSWp/cKncYgD5WxE
CpAnRUXG2pG4zdkzCYzAh1i+c34L6oZoHsirK6oNcEnHveydfzJL5934egm6p8DW
+m1RQ70yUt4uRc0YSor+q1LGJvGQHReF0WmJBZHrhz5e63Pq7lE0gIwuBqL8SMaA
yRXtK+JGxZpImTq+NHvEWWCu09SCq0r838ceQI55SvzmTkwqtC+8AT2zFviMZkKR
Qo6SPsrqItxZWRty2izawTF0Bf5S2VAx7O+6t3wBsQ1sLptoSgX3QblELY5asI0J
YFz7LJECgYkAsqeUJmqXE3LP8tYoIjMIAKiTm9o6psPlc8CrLI9CH0UbuaA2JCOM
cCNq8SyYbTqgnWlB9ZfcAm/cFpA8tYci9m5vYK8HNxQr+8FS3Qo8N9RJ8d0U5Csw
DzMYfRghAfUGwmlWj5hp1pQzAuhwbOXFtxKHVsMPhz1IBtF9Y8jvgqgYHLbmyiu1
mwJ5AL0pYF0G7x81prlARURwHo0Yf52kEw1dxpx+JXER7hQRWQki5/NsUEtv+8RT
qn2m6qte5DXLyn83b1qRscSdnCCwKtKWUug5q2ZbwVOCJCtmRwmnP131lWRYfj67
B/xJ1ZA6X3GEf4sNReNAtaucPEelgR2nsN0gKQKBiGoqHWbK1qYvBxX2X3kbPDkv
9C+celgZd2PW7aGYLCHq7nPbmfDV0yHcWjOhXZ8jRMjmANVR/eLQ2EfsRLdW69bn
f3ZD7JS1fwGnO3exGmHO3HZG+6AvberKYVYNHahNFEw5TsAcQWDLRpkGybBcxqZo
81YCqlqidwfeO5YtlO7etx1xLyqa2NsCeG9A86UjG+aeNnXEIDk1PDK+EuiThIUa
/2IxKzJKWl1BKr2d4xAfR0ZnEYuRrbeDQYgTImOlfW6/GuYIxKYgEKCFHFqJATAG
IxHrq1PDOiSwXd2GmVVYyEmhZnbcp8CxaEMQoevxAta0ssMK3w6UsDtvUvYvF22m
qQKBiD5GwESzsFPy3Ga0MvZpn3D6EJQLgsnrtUPZx+z2Ep2x0xc5orneB5fGyF1P
WtP+fG5Q6Dpdz3LRfm+KwBCWFKQjg7uTxcjerhBWEYPmEMKYwTJF5PBG9/ddvHLQ
EQeNC8fHGg4UXU8mhHnSBt3EA10qQJfRDs15M38eG2cYwB1PZpDHScDnDA0=
-----END RSA PRIVATE KEY-----`))

func publicKeyDecode(data []byte) *rsa.PublicKey {
	block, _ := pem.Decode(data)
	key, _ := x509.ParsePKCS1PublicKey(block.Bytes)
	return key
}

func privateKeyDecode(data []byte) *rsa.PrivateKey {
	block, _ := pem.Decode(data)
	key, _ := x509.ParsePKCS1PrivateKey(block.Bytes)
	return key
}

// -----------------------------------------------------------------------------

// Extracted from spec
// https://www.ietf.org/id/draft-ietf-httpbis-message-signatures-01.html#name-test-cases
func sampleRequest() *http.Request {
	r, err := http.ReadRequest(bufio.NewReader(bytes.NewBufferString(`POST /foo?param=value&pet=dog HTTP/1.1
Host: example.com
Date: Tue, 07 Jun 2014 20:51:35 GMT
Content-Type: application/json
Digest: SHA-256=X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=
Content-Length: 18

{"hello": "world"}`)))
	if err != nil {
		panic(err)
	}

	return r
}

// -----------------------------------------------------------------------------

// https://www.ietf.org/id/draft-ietf-httpbis-message-signatures-01.html#section-a.3.1.1
func Test_SigGen_HS2019Minimal(t *testing.T) {
	si := &httpsig.SignatureInput{
		ID:        "sig1",
		Algorithm: httpsig.AlgorithmHS2019,
		KeyID:     "test-key-a",
		Created:   1402170695,
		Headers:   []string{"*created", "*request-target"},
	}

	// Assert conanical syntax
	expectedCanonical := `sig1=(*created, *request-target); alg="hs2019"; kid="test-key-a"; created=1402170695`
	if si.String() != expectedCanonical {
		t.Fatalf("invalid canonical syntax expected `%s`, got `%s`", expectedCanonical, si.String())
	}

	// Create operations
	signer := httpsig.NewSigner(func(ctx context.Context, kid string) (interface{}, error) {
		return testRSAPrivateKey, nil
	})
	verifier := httpsig.NewVerifier(func(ctx context.Context, kid string) (interface{}, error) {
		return testRSAPublicKey, nil
	})

	// Create request
	r := sampleRequest()

	sig, err := signer.Sign(context.Background(), si, r)
	if err != nil {
		t.Fatalf("unable to sign: %v", err)
	}

	valid, errVerify := verifier.Verify(context.Background(), si, sig, r)
	if errVerify != nil {
		t.Fatalf("unable to verify: %v", errVerify)
	}

	// Expected
	if !valid {
		t.Fatalf("expected valid, got %v", valid)
	}
}

// https://www.ietf.org/id/draft-ietf-httpbis-message-signatures-01.html#section-a.3.1.1
func Test_SigGen_Default(t *testing.T) {
	si := httpsig.DefaultSignatureInput("test-key-a")

	// Create operations
	signer := httpsig.NewSigner(func(ctx context.Context, kid string) (interface{}, error) {
		return testRSAPrivateKey, nil
	})
	verifier := httpsig.NewVerifier(func(ctx context.Context, kid string) (interface{}, error) {
		return testRSAPublicKey, nil
	})

	// Create request
	r := sampleRequest()

	sig, err := signer.Sign(context.Background(), si, r)
	if err != nil {
		t.Fatalf("unable to sign: %v", err)
	}

	valid, errVerify := verifier.Verify(context.Background(), si, sig, r)
	if errVerify != nil {
		t.Fatalf("unable to verify: %v", errVerify)
	}

	// Expected
	if !valid {
		t.Fatalf("expected valid, got %v", valid)
	}
}

// https://www.ietf.org/id/draft-ietf-httpbis-message-signatures-01.html#name-hs2019-signature-covering-a
func Test_SigGen_HS2019AllFields(t *testing.T) {
	si := &httpsig.SignatureInput{
		ID:        "sig1",
		Algorithm: httpsig.AlgorithmHS2019,
		KeyID:     "test-key-a",
		Created:   1402170695,
		Headers:   []string{"*created", "*request-target", "host", "date", "content-type", "digest", "content-length"},
	}

	// Assert conanical syntax
	expectedCanonical := `sig1=(*created, *request-target, host, date, content-type, digest, content-length); alg="hs2019"; kid="test-key-a"; created=1402170695`
	if si.String() != expectedCanonical {
		t.Fatalf("invalid canonical syntax expected `%s`, got `%s`", expectedCanonical, si.String())
	}

	// Create operations
	signer := httpsig.NewSigner(func(ctx context.Context, kid string) (interface{}, error) {
		return testRSAPrivateKey, nil
	})
	verifier := httpsig.NewVerifier(func(ctx context.Context, kid string) (interface{}, error) {
		return testRSAPublicKey, nil
	})

	// Create request
	r := sampleRequest()

	sig, err := signer.Sign(context.Background(), si, r)
	if err != nil {
		t.Fatalf("unable to sign: %v", err)
	}

	valid, errVerify := verifier.Verify(context.Background(), si, sig, r)
	if errVerify != nil {
		t.Fatalf("unable to verify: %v", errVerify)
	}

	// Expected
	if !valid {
		t.Fatalf("expected valid, got %v", valid)
	}
}

// https://www.ietf.org/id/draft-ietf-httpbis-message-signatures-01.html#name-minimal-required-signature-
func Test_SigVer_Minimal(t *testing.T) {
	rawSigInput := `sig1=(); kid="test-key-a"; created=1402170695`
	rawSignature := `sig1=:F0KlO2pMfxIbW11zInSXIciUA517Q+MLclZoWd0zEwAgLPriBudnbrjd6C6+OKsEX1hxlFchALhZ4eTso/7iHgRZV2geuIrtBOjPMRiTJc8OIEvCUc518JYQK4ZXUfLx58Gp1gggWPf9Eh/2xdRl0dIFTvdX8B9im+kEMaMT+fA1OB/T643P2d9MZRkAVQUnmZA2/atH+sbCjNeeOniWe7Bk3HYvrYUHNnFXjApbzSO97goK9O5zONqkJ8vjnZtynotXaL+fAsGxAiDwXXVZ8JLXrAAu/k7gdkgq0o5oxSNBPtKBAI5EogfZBN9k87lWBfcqNV2ZQd+UJ8TMAziYEQ==:`

	// Parse signature-inputs
	sigInputs, err := httpsig.ParseSignatureInput(rawSigInput)
	if err != nil {
		t.Fatalf("unexpected error httpsig.ParseSignatureInput(), got %v", err)
	}

	// Create operations
	verifier := httpsig.NewVerifier(func(ctx context.Context, kid string) (interface{}, error) {
		return testRSAPublicKey, nil
	})

	// Create request
	r := sampleRequest()

	// Parse signature set
	signatures, err := httpsig.ParseSignatureSet(rawSignature)
	if err != nil {
		t.Fatalf("unexpected error httpsig.ParseSignatureSet(), got %v", err)
	}
	sigFromSigSet, _ := signatures.Get(sigInputs[0].ID)

	// Check validity
	valid, errVerify := verifier.Verify(context.Background(), sigInputs[0], sigFromSigSet, r)
	if errVerify != nil {
		t.Fatalf("unable to verify: %v", errVerify)
	}

	// Expected
	if !valid {
		t.Fatalf("expected valid, got %v", valid)
	}
}

// https://www.ietf.org/id/draft-ietf-httpbis-message-signatures-01.html#section-a.3.2.2
func Test_SigVer_Minimal_Recommended(t *testing.T) {
	rawSigInput := `sig1=(); alg=hs2019; kid="test-key-a"; created=1402170695`
	rawSignature := `sig1=:F0KlO2pMfxIbW11zInSXIciUA517Q+MLclZoWd0zEwAgLPriBudnbrjd6C6+OKsEX1hxlFchALhZ4eTso/7iHgRZV2geuIrtBOjPMRiTJc8OIEvCUc518JYQK4ZXUfLx58Gp1gggWPf9Eh/2xdRl0dIFTvdX8B9im+kEMaMT+fA1OB/T643P2d9MZRkAVQUnmZA2/atH+sbCjNeeOniWe7Bk3HYvrYUHNnFXjApbzSO97goK9O5zONqkJ8vjnZtynotXaL+fAsGxAiDwXXVZ8JLXrAAu/k7gdkgq0o5oxSNBPtKBAI5EogfZBN9k87lWBfcqNV2ZQd+UJ8TMAziYEQ==:`

	// Parse signature-inputs
	sigInputs, err := httpsig.ParseSignatureInput(rawSigInput)
	if err != nil {
		t.Fatalf("unexpected error httpsig.ParseSignatureInput(), got %v", err)
	}

	// Create operations
	verifier := httpsig.NewVerifier(func(ctx context.Context, kid string) (interface{}, error) {
		return testRSAPublicKey, nil
	})

	// Create request
	r := sampleRequest()

	// Parse signature set
	signatures, err := httpsig.ParseSignatureSet(rawSignature)
	if err != nil {
		t.Fatalf("unexpected error httpsig.ParseSignatureSet(), got %v", err)
	}
	sigFromSigSet, _ := signatures.Get(sigInputs[0].ID)

	// Check validity
	valid, errVerify := verifier.Verify(context.Background(), sigInputs[0], sigFromSigSet, r)
	if errVerify != nil {
		t.Fatalf("unable to verify: %v", errVerify)
	}

	// Expected
	if !valid {
		t.Fatalf("expected valid, got %v", valid)
	}
}
