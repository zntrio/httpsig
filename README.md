# HTTP Request Signature

Use [RFC 8941](https://www.rfc-editor.org/rfc/rfc8941.html) (a.k.a. Structured Field Values) to implements
the draft specification [draft-ietf-httpbis-message-signatures](https://www.ietf.org/archive/id/draft-ietf-httpbis-message-signatures-05.html)(version 5).

> Message integrity and authenticity are important security properties that are critical to the secure operation of many HTTP applications. Application developers typically rely on the transport layer to provide these properties, by operating their application over [TLS]. However, TLS only guarantees these properties over a single TLS connection, and the path between client and application may be composed of multiple independent TLS connections (for example, if the application is hosted behind a TLS-terminating gateway or if the client is behind a TLS Inspection appliance). In such cases, TLS cannot guarantee end-to-end message integrity or authenticity between the client and application. Additionally, some operating environments present obstacles that make it impractical to use TLS, or to use features necessary to provide message authenticity. Furthermore, some applications require the binding of an application-level key to the HTTP message, separate from any TLS certificates in use. Consequently, while TLS can meet message integrity and authenticity needs for many HTTP-based applications, it is not a universal solution.

## Limitations

* can't reproduce `RSASSA-PSS` signatures from standard because Go can't load these kind of private keys.
* Algorithms supported
  * `rsa-pss-sha512` (equiv. JWA PS512)
  * `rsa-v1_5-sha256` (equiv. JWA RS256)
  * `hmac-sha256` (equiv. JWA HS256)
  * `ecdsa-p256-sha256` '(equiv. JWA ES256)
  * `eddsa-ed25519-sha512` (not in the standard) (equiv JWA EdDSA)

## Protocol

### HTTP

`Signature-Input` - HTTP Header

> Contains a Dictionary typed Structured Field Value (RFC8941)

* `key` is the definition identifier
* `value` is a `List with Params`

```sh
Signature-Input: sig1=(@request-target, @created, host, date,
    cache-control, x-empty-header, x-example); keyid="test-key-a";
    alg="rsa-pss-sha512"; created=1402170695; expires=1402170995
```

`Signature` - HTTP Header

> Contains a Dictionary typed Structured Field Value (RFC8941)

* `key` is the definition identifier
* `value` is an `Item` containing `Binary` base64 encoded byte array

```sh
Signature: sig1=:K2qGT5srn2OGbOIDzQ6kYT+ruaycnDAAUpKv+ePFfD0RAxn/1BUe
    Zx/Kdrq32DrfakQ6bPsvB9aqZqognNT6be4olHROIkeV879RrsrObury8L9SCEibe
    oHyqU/yCjphSmEdd7WD+zrchK57quskKwRefy2iEC5S2uAH0EPyOZKWlvbKmKu5q4
    CaB8X/I5/+HLZLGvDiezqi6/7p2Gngf5hwZ0lSdy39vyNMaaAT0tKo6nuVw0S1MVg
    1Q7MpWYZs0soHjttq0uLIA3DIbQfLiIvK6/l0BdWTU7+2uQj7lBkQAsFZHoA96ZZg
    FquQrXRlmYOh+Hx5D9fJkXcXe5tmAg==:
```

## Sample

Sign a request

```go
// Generate a key
priv, pub := rsa.GenerateKey(rand.Reader, 2048)

// Prepare a signature-input
si := httpsig.SignatureInput{
  ID: "sig1",
  KeyID: "my-wonderful-key-identifier",
  Headers: []string{"@created","@request-target","Authorization"},
  Created: uint64(time.Now().Unix()),
  Nonce: uniuri.NewLen(32),
}

// Key resolver function
privateKeyResolver := func(ctx context.Context, kid string){
  return priv, nil
}

// Prepare a signer
signer := httpsig.NewSigner(httpsig.AlgorithmRSAPSSSHA512, privateKeyResolver)

// Create your request
req := http.NewRequest(...)

// Generate the signature
sig, err := signer.Sign(context.Background(), si, r)
if err != nil {
  ...
}

// Prepare signature set
signSet := &httpsig.SignatureSet{}
signSet.Add(si.ID(), sig)

// Assign to request headers.
req.Header.Set("Signature-Input", si.String())
req.Header.Set("Signature", signSet.String())
```

Verify a request

```go
// Key resolver function (database / cache / file)
publicKeyResolver := func(ctx context.Context, kid string){
  return pub, nil
}

// Prepare a verifier
verifier := httpsig.NewVerifier(publicKeyResolver)

// Extract information from request
inputs, _ := httpsig.ParseSignatureInput(req.Header.Get("Signature-Input"))
signatures, _ := httpsig.ParseSignatureSet(req.Header.Get("Signature"))

// Check all signatures
for _, si := range inputs {
  sig, ok := signatures.Get(si.ID)
  if !ok {
    ... Signature not found
  }

  // Crypto verification
  sig, err := verifier.Verify(context.Background(), si, sig, r)
  if err != nil {
    ... Error during verification
  }
}
```

Using a custom `RoundTripper`

```go
type SignerTransport struct {
  http.RoundTripper
  Signer httpsig.Signer
  KeyID  string
}

func (ct *SignerTransport) RoundTrip(req *http.Request) (*http.Response, error) {
  // Prepare a signature-input
  si := httpsig.SignatureInput{
    ID: "sig1",
    KeyID: ct.KeyID,
    Headers: []string{"@request-target", "host", "Authorization", "Digest"},
    Created: uint64(time.Now().Unix()),
    Nonce: uniuri.NewLen(32),
  }

  // Generate the signature
  sig, err := ct.Signer.Sign(req.Context(), si, r)
  if err != nil {
    return nil, fmt.Errorf("unable to sign the request: %w", err)
  }

  // Prepare signature set
  signSet := &httpsig.SignatureSet{}
  signSet.Add(si.ID(), sig)

  // Assign to request headers.
  req.Header.Set("Signature-Input", si.String())
  req.Header.Set("Signature", signSet.String())

  // Delegate to parent RoundTripper
  return ct.RoundTripper.RoundTrip(req)
}

// Create a HTTP client with custom transport.
url := "http://localhost:8200/api/v1/resource"
tr := &SignerTransport{
  Signer: signer,
  KeyID: "client-public-keyid",
}
client := &http.Client{Transport: tr}
resp, err := client.Get(url)
```
