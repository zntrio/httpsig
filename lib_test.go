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
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"net/http"
	"testing"

	"zntr.io/httpsig"
)

// -----------------------------------------------------------------------------

func rsaPKCS1PublicKeyDecode(data []byte) *rsa.PublicKey {
	block, _ := pem.Decode(data)
	key, _ := x509.ParsePKCS1PublicKey(block.Bytes)
	if key == nil {
		panic("key must not be nil")
	}
	return key
}

func rsaPKCS1PrivateKeyDecode(data []byte) *rsa.PrivateKey {
	block, _ := pem.Decode(data)
	key, _ := x509.ParsePKCS1PrivateKey(block.Bytes)
	if key == nil {
		panic("key must not be nil")
	}
	return key
}

func eccPrivateKeyDecode(data []byte) *ecdsa.PrivateKey {
	block, _ := pem.Decode(data)
	key, _ := x509.ParseECPrivateKey(block.Bytes)
	if key == nil {
		panic("key must not be nil")
	}
	return key
}

func eccPublicKeyDecode(data []byte) *ecdsa.PublicKey {
	block, _ := pem.Decode(data)
	key, _ := x509.ParsePKIXPublicKey(block.Bytes)
	if key == nil {
		panic("key must not be nil")
	}
	return key.(*ecdsa.PublicKey)
}

// -----------------------------------------------------------------------------

// Imported from spec.
// https://www.ietf.org/archive/id/draft-ietf-httpbis-message-signatures-05.html#section-b.1.1

var testRSAPublicKey = rsaPKCS1PublicKeyDecode([]byte(`-----BEGIN RSA PUBLIC KEY-----
MIIBCgKCAQEAhAKYdtoeoy8zcAcR874L8cnZxKzAGwd7v36APp7Pv6Q2jdsPBRrw
WEBnez6d0UDKDwGbc6nxfEXAy5mbhgajzrw3MOEt8uA5txSKobBpKDeBLOsdJKFq
MGmXCQvEG7YemcxDTRPxAleIAgYYRjTSd/QBwVW9OwNFhekro3RtlinV0a75jfZg
kne/YiktSvLG34lw2zqXBDTC5NHROUqGTlML4PlNZS5Ri2U4aCNx2rUPRcKIlE0P
uKxI4T+HIaFpv8+rdV6eUgOrB2xeI1dSFFn/nnv5OoZJEIB+VmuKn3DCUcCZSFlQ
PSXSfBDiUGhwOw76WuSSsf1D4b/vLoJ10wIDAQAB
-----END RSA PUBLIC KEY-----`))

var testRSAPrivateKey = rsaPKCS1PrivateKeyDecode([]byte(`-----BEGIN RSA PRIVATE KEY-----
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

// -----------------------------------------------------------------------------

// Imported from spec.
// https://www.ietf.org/archive/id/draft-ietf-httpbis-message-signatures-05.html#section-b.1.3

var testECCP256PublicKey = eccPublicKeyDecode([]byte(`-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEqIVYZVLCrPZHGHjP17CTW0/+D9Lf
w0EkjqF7xB4FivAxzic30tMM4GF+hR6Dxh71Z50VGGdldkkDXZCnTNnoXQ==
-----END PUBLIC KEY-----`))

var testECCP256PrivateKey = eccPrivateKeyDecode([]byte(`-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIFKbhfNZfpDsW43+0+JjUr9K+bTeuxopu653+hBaXGA7oAoGCCqGSM49
AwEHoUQDQgAEqIVYZVLCrPZHGHjP17CTW0/+D9Lfw0EkjqF7xB4FivAxzic30tMM
4GF+hR6Dxh71Z50VGGdldkkDXZCnTNnoXQ==
-----END EC PRIVATE KEY-----`))

// -----------------------------------------------------------------------------

// Imported from spec.
// https://www.ietf.org/archive/id/draft-ietf-httpbis-message-signatures-05.html#section-b.1.3

// -----------------------------------------------------------------------------

// Extracted from spec
// https://www.ietf.org/archive/id/draft-ietf-httpbis-message-signatures-05.html#section-b.2
func sampleTestRequest() *http.Request {
	r, err := http.ReadRequest(bufio.NewReader(bytes.NewBufferString(`POST /foo?param=value&pet=dog HTTP/1.1
Host: example.com
Date: Tue, 20 Apr 2021 02:07:55 GMT
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

// https://www.ietf.org/archive/id/draft-ietf-httpbis-message-signatures-05.html#section-b.2.1
func Test_SigGen_Minimal(t *testing.T) {
	rawSigInput := `sig1=();created=1618884475;keyid="test-key-rsa-pss";alg="rsa-pss-sha512"`

	// Parse signature-inputs
	sigInputs, err := httpsig.ParseSignatureInput(rawSigInput)
	if err != nil {
		t.Fatalf("unexpected error httpsig.ParseSignatureInput(), got %v", err)
	}

	// Create signer
	signer := httpsig.NewSigner(httpsig.AlgorithmRSAPSSSHA512, func(ctx context.Context, kid string) (interface{}, error) {
		return testRSAPrivateKey, nil
	})
	verifier := httpsig.NewVerifier(func(ctx context.Context, kid string) (interface{}, error) {
		return testRSAPublicKey, nil
	})

	// Create request
	r := sampleTestRequest()

	sig, err := signer.Sign(context.Background(), sigInputs[0], r)
	if err != nil {
		t.Fatalf("unable to sign: %v", err)
	}

	valid, errVerify := verifier.Verify(context.Background(), sigInputs[0], sig, r)
	if errVerify != nil {
		t.Fatalf("unable to verify: %v", errVerify)
	}

	// Expected
	if !valid {
		t.Fatalf("expected valid, got %v", valid)
	}
}
