go-saml
======

Forked from [https://github.com/RobotsAndPencils/go-saml](https://github.com/RobotsAndPencils/go-saml)

A just good enough SAML client library written in Go.

The library supports:

* generating signed/unsigned AuthnRequests and Responses
* validating signed AuthnRequests and Responses
* generating service provider metadata

Usage
-----

Below are samples to show how you might use the library.

### Generating Signed AuthnRequests

```go
sp := &saml.ServiceProvider{
  IDPSSOURL:                   "http://idp/saml2", // idp's authentication url
  IDPPublicCert:               idpPublicCert, // x502.Certificate of the IDP's public cert
  IssuerURL:                   "http://localhost:8000", // your SP URL
  AssertionConsumerServiceURL: "http://localhost:8000/saml_consume", // your callback url after authentication at IDP
  PrivateKey:                  privateKey, // rsa.PrivateKey for your SP
  PublicCert:                  publicCert, // x502.Certificate corresponding to privateKey
  SignRequest:                 true, // whether to sign authentication requests
  UseCompression:              true, // whether to compress requests and decompress responses
}

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
  resp, err := sp.ParseEncodedResponse(encodedXML)
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
