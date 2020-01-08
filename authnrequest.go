package saml

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/xml"
	"fmt"
	"time"

	"github.com/janrain/go-saml/util"
	"github.com/janrain/go-saml/xmldsig"
)

// ParseAuthnRequest parses a SAML AuthnRequest
func ParseAuthnRequest(rawXML string) (*AuthnRequest, error) {
	ar := &AuthnRequest{}
	err := xml.Unmarshal([]byte(rawXML), ar)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal xml: %w", err)
	}

	// There is a bug with XML namespaces in Go that's causing them to not be roundtrip
	// marshal and unmarshaled so we'll keep the original string around for validation.
	ar.originalString = rawXML
	return ar, nil
}

// ParseEncodedAuthnRequest parses an encoded, possibly compressed SAML AuthnRequest
func ParseEncodedAuthnRequest(encodedXML string) (*AuthnRequest, error) {
	decodedXML, err := base64.StdEncoding.DecodeString(encodedXML)
	if err != nil {
		return nil, fmt.Errorf("failed to decode xml: %w", err)
	}

	decompressedXML, err := util.Decompress(decodedXML)
	if err == nil {
		decodedXML = decompressedXML
	}
	// if there was an error during decompression, assume it wasn't compressed

	return ParseAuthnRequest(string(decodedXML))
}

// NewAuthnRequest constructs an AuthnRequest
// issuer should be the SP URL
// acs should be the SP ACS URL
// destination should IDP URL
func NewAuthnRequest(issuer, acs, destination string) *AuthnRequest {
	return &AuthnRequest{
		XMLName: xml.Name{
			Local: "samlp:AuthnRequest",
		},
		SAMLP:                       "urn:oasis:names:tc:SAML:2.0:protocol",
		SAML:                        "urn:oasis:names:tc:SAML:2.0:assertion",
		ID:                          util.ID(),
		ProtocolBinding:             "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
		Version:                     "2.0",
		AssertionConsumerServiceURL: acs,
		Destination:                 destination,
		Issuer: Issuer{
			XMLName: xml.Name{
				Local: "saml:Issuer",
			},
			SAML:  "urn:oasis:names:tc:SAML:2.0:assertion",
			Value: issuer,
		},
		IssueInstant: time.Now().UTC().Format(time.RFC3339),
		NameIDPolicy: NameIDPolicy{
			XMLName: xml.Name{
				Local: "samlp:NameIDPolicy",
			},
			AllowCreate: true,
			Format:      "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified",
		},
		RequestedAuthnContext: RequestedAuthnContext{
			XMLName: xml.Name{
				Local: "samlp:RequestedAuthnContext",
			},
			SAMLP:      "urn:oasis:names:tc:SAML:2.0:protocol",
			Comparison: "exact",
			AuthnContextClassRef: AuthnContextClassRef{
				XMLName: xml.Name{
					Local: "saml:AuthnContextClassRef",
				},
				SAML:      "urn:oasis:names:tc:SAML:2.0:assertion",
				Transport: "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport",
			},
		},
	}
}

// String returns the request as a string
func (ar *AuthnRequest) String() (string, error) {
	b, err := xml.MarshalIndent(ar, "", "\t")
	if err != nil {
		return "", fmt.Errorf("failed to marshal xml: %w", err)
	}

	return string(b), nil
}

// SignedString returns the request as a string with signature included
func (ar *AuthnRequest) SignedString(xPath string, privateKey *rsa.PrivateKey, publicCert *x509.Certificate) (string, error) {
	s, err := ar.String()
	if err != nil {
		return "", err
	}

	return xmldsig.Sign(s, xPath, privateKey, publicCert)
}

// EncodedSignedString returns the request base64 encoded and signed
func (ar *AuthnRequest) EncodedSignedString(xPath string, privateKey *rsa.PrivateKey, publicCert *x509.Certificate) (string, error) {
	signed, err := ar.SignedString(xPath, privateKey, publicCert)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString([]byte(signed)), nil
}

// CompressedEncodedSignedString returns the request compressed, base64 encoded, and signed
func (ar *AuthnRequest) CompressedEncodedSignedString(xPath string, privateKey *rsa.PrivateKey, publicCert *x509.Certificate) (string, error) {
	signed, err := ar.SignedString(xPath, privateKey, publicCert)
	if err != nil {
		return "", err
	}
	compressed := util.Compress([]byte(signed))
	return base64.StdEncoding.EncodeToString(compressed), nil
}

// EncodedString returns the request base64 encoded
func (ar *AuthnRequest) EncodedString() (string, error) {
	s, err := ar.String()
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString([]byte(s)), nil
}

// CompressedEncodedString returns the request compressed and base64 encoded
func (ar *AuthnRequest) CompressedEncodedString() (string, error) {
	s, err := ar.String()
	if err != nil {
		return "", err
	}
	compressed := util.Compress([]byte(s))
	return base64.StdEncoding.EncodeToString(compressed), nil
}

// VerifySignature verifies the signature
func (ar *AuthnRequest) VerifySignature(xPath string, certs []*x509.Certificate) error {
	return xmldsig.VerifySignature(ar.originalString, xPath, certs)
}
