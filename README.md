# HTTP Request Signature

Use [RFC 8941](https://www.rfc-editor.org/rfc/rfc8941.html) (a.k.a. Structured Field Values) to implements
the draft specification [draft-ietf-httpbis-message-signatures](https://www.ietf.org/id/draft-ietf-httpbis-message-signatures-01.html).

## Limitations

* Only `hs2019` suite is supported
* No inner request header resolver

## Sample

Sign a request

```go
// Generate a key
pub, priv, _ := ed25519.GenerateKey(rand.Reader)

// Prepare a signature-input
si := httpsig.SignatureInput{
  ID: "sig1",
  KeyID: "my-wonderful-key-identifier",
  Headers: []string{"*created","*request-target","Authorization"},
  Created: uint64(time.Now().Unix()),
}

// Key resolver function
privateKeyResolver := func(ctx context.Context, kid string){
  return priv, nil
}

// Prepare a signer
signer := httpsig.NewSigner(privateKeyResolver)

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
inputs, _ := httpsig.ParseSignatrueInput(req.Header.Get("Signature-Input"))
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
