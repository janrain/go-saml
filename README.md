go-saml
======

Forked from [https://github.com/RobotsAndPencils/go-saml](https://github.com/RobotsAndPencils/go-saml)

A just good enough SAML client library written in Go.

The library supports:

* generating signed/unsigned AuthnRequests
* validating signed Responses
* generating service provider metadata

### Prerequisites

The `xmlsec1` command must be installed - this library uses it to
sign and verify XML signatures.

Usage
-----

Below are samples to show how you might use the library.

### Generating Signed AuthnRequests

```go
sp := &saml.ServiceProvider{
  IDPSSOURL:                   "http://idp/saml2", // idp's authentication url
  IDPPublicCertPath:           "/certs/idpcert.crt", // filesystem path to idp's cert
  IssuerURL:                   "http://localhost:8000", // your base url
  AssertionConsumerServiceURL: "http://localhost:8000/saml_consume", // your callback url after authentication at IDP
  PublicCertPath:              "/certs/default.crt", // filesystem path to your cert
  PrivateKeyPath:              "/certs/default.key", // filesystem path to your private key
  SignRequest:                 true, // whether to sign authentication requests
  UseCompression:              true, // whether to compress requests and decompress responses
}
sp.Init()

// generate the AuthnRequest
authnRequest := sp.AuthnRequest()

// get a base64 encoded string of the XML
b64XML, err := sp.EncodeAuthnRequest(authnRequest)
if err != nil {
  panic(err)
}

// get a URL with the SAMLRequest parameter containing the encoded XML
url, err := sp.AuthnRequestURL(b64XML, "some state value")
if err != nil {
  panic(err)
}
```

### Validating a received SAML Response


```go
  resp, err := sp.ParseResponse(encodedXML)
  if err != nil {
    panic(err)
  }

  err = sp.ValidateResponse(resp)
  if err != nil {
    panic(err)
  }

  subject := resp.Assertion.Subject.NameID.Value
  for _, attr := range resp.Assertion.AttributeStatement.Attributes {
    // process attributes...
  }
  //...
}
```

### Service provider metadata

```go
func samlMetadataHandler(sp *saml.ServiceProvider) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		md, err := sp.EntityDescriptorXML()
		if err != nil {
      panic(err)
		}

		w.Header().Set("Content-Type", "application/xml")
		w.Write([]byte(md))
	})
}
```
