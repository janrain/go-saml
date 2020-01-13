package saml

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/xml"
	"errors"
	"fmt"
	"time"

	"github.com/janrain/go-saml/util"
	"github.com/janrain/go-saml/xmldsig"

	"github.com/beevik/etree"
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
	ac := true
	allowCreate := &ac
	f := "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified"
	format := &f
	return &AuthnRequest{
		ID:                          util.ID(),
		ProtocolBinding:             "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
		Version:                     "2.0",
		AssertionConsumerServiceURL: acs,
		Destination:                 destination,
		Issuer: &Issuer{
			Value: issuer,
		},
		IssueInstant: time.Now().UTC().Format(time.RFC3339),
		NameIDPolicy: &NameIDPolicy{
			AllowCreate: allowCreate,
			Format:      format,
		},
		RequestedAuthnContext: &RequestedAuthnContext{
			Comparison: "exact",
			AuthnContextClassRef: &AuthnContextClassRef{
				Transport: "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport",
			},
		},
	}
}

// Sign adds a signature to the request
func (ar *AuthnRequest) Sign(privateKey *rsa.PrivateKey, publicCert *x509.Certificate) error {
	sig, err := xmldsig.Sign(ar.Element(), privateKey, publicCert)
	if err != nil {
		return err
	}
	ar.Signature = sig
	return nil
}

// String returns the request as a string
func (ar *AuthnRequest) String() (string, error) {
	doc := etree.NewDocument()
	doc.SetRoot(ar.Element())
	return doc.WriteToString()
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

// ValidateSignature checks the signature in the request
func (ar *AuthnRequest) ValidateSignature(certs []*x509.Certificate) error {
	// if this is a parsed request the signature will be missing
	// so we have to use the original xml
	if ar.originalString != "" {
		return ValidateAuthnRequestSignature(ar.originalString, certs)
	}
	if ar.Signature != nil {
		return xmldsig.VerifySignature(ar.Element(), certs)
	}
	return errors.New("signature not found")
}

// ValidateResponseSignature verifies signature(s) in a AuthnRequest XML document.
func ValidateAuthnRequestSignature(rawXML string, certs []*x509.Certificate) error {
	doc := etree.NewDocument()
	err := doc.ReadFromString(rawXML)
	if err != nil {
		return err
	}

	root := doc.Root()
	if root == nil {
		return errors.New("root element not found")
	}
	if root.Tag != "AuthnRequest" {
		return fmt.Errorf("root element is not AuthnRequest, found %s instead", root.Tag)
	}

	for _, rootChild := range root.ChildElements() {
		if rootChild.Tag == "Signature" {
			return xmldsig.VerifySignature(root, certs)
		}
	}

	return errors.New("signature not found")
}
