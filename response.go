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

// ParseResponse parses a SAML Response
func ParseResponse(rawXML string) (*Response, error) {
	resp := &Response{}
	err := xml.Unmarshal([]byte(rawXML), resp)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal xml: %w", err)
	}
	// There is a bug with XML namespaces in Go that's causing them to not be roundtrip
	// marshal and unmarshaled so we'll keep the original string around for validation.
	resp.originalString = rawXML
	return resp, nil
}

// ParseEncodedResponse parses an encoded, possibly compressed SAML Response
func ParseEncodedResponse(encodedXML string) (*Response, error) {
	decodedXML, err := base64.StdEncoding.DecodeString(encodedXML)
	if err != nil {
		return nil, fmt.Errorf("failed to decode xml: %w", err)
	}

	decompressedXML, err := util.Decompress(decodedXML)
	if err == nil {
		decodedXML = decompressedXML
	}
	// if there was an error during decompression, assume it wasn't compressed

	return ParseResponse(string(decodedXML))
}

// NewResponse creates a new Response
// issuer should be the IDP URL
// audience should be the SP entityID
// destination should be the SP ACS URL
// subject should be the identifier of the assertion subject
func NewResponse(issuer, audience, destination, subject string) *Response {
	now := time.Now().UTC()
	return &Response{
		ID:           util.ID(),
		Version:      "2.0",
		IssueInstant: now.Format(time.RFC3339Nano),
		Issuer: &Issuer{
			Value: issuer,
		},
		Destination: destination,
		Status: Status{
			StatusCode: StatusCode{
				Value: "urn:oasis:names:tc:SAML:2.0:status:Success",
			},
		},
		Assertion: &Assertion{
			Version:      "2.0",
			ID:           util.ID(),
			IssueInstant: now.Format(time.RFC3339Nano),
			Issuer: Issuer{
				Value: issuer,
			},
			Subject: &Subject{
				NameID: &NameID{
					Format: "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified",
					Value:  subject,
				},
				SubjectConfirmation: &SubjectConfirmation{
					Method: "urn:oasis:names:tc:SAML:2.0:cm:bearer",
					SubjectConfirmationData: &SubjectConfirmationData{
						NotOnOrAfter: now.Add(time.Minute * 5).Format(time.RFC3339Nano),
						Recipient:    destination,
					},
				},
			},
			Conditions: &Conditions{
				NotBefore:    now.Add(time.Minute * -5).Format(time.RFC3339Nano),
				NotOnOrAfter: now.Add(time.Minute * 5).Format(time.RFC3339Nano),
				AudienceRestriction: &AudienceRestriction{
					Audience: Audience{
						Value: audience,
					},
				},
			},
			AttributeStatement: &AttributeStatement{
				Attributes: []Attribute{},
			},
		},
	}
}

// AddAttribute adds an attribute to the response assertion
func (resp *Response) AddAttribute(name, value string) {
	resp.Assertion.AttributeStatement.Attributes = append(resp.Assertion.AttributeStatement.Attributes, Attribute{
		Name:       name,
		NameFormat: "urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified",
		AttributeValues: []AttributeValue{
			{
				Type:  "xs:string",
				Value: value,
			},
		},
	})
}

// SignAssertion adds a signature to the assertion
func (resp *Response) SignAssertion(privateKey *rsa.PrivateKey, publicCert *x509.Certificate) error {
	sig, err := xmldsig.Sign(resp.Assertion.Element(), privateKey, publicCert)
	if err != nil {
		return err
	}
	resp.Assertion.Signature = sig
	return nil
}

// SignResponse adds a signature to the response
func (resp *Response) SignResponse(privateKey *rsa.PrivateKey, publicCert *x509.Certificate) error {
	sig, err := xmldsig.Sign(resp.Element(), privateKey, publicCert)
	if err != nil {
		return err
	}
	resp.Signature = sig
	return nil
}

// String returns the response as a string
func (resp *Response) String() (string, error) {
	doc := etree.NewDocument()
	doc.SetRoot(resp.Element())
	return doc.WriteToString()
}

// EncodedString returns the response base64 encoded
func (resp *Response) EncodedString() (string, error) {
	s, err := resp.String()
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString([]byte(s)), nil
}

// CompressedEncodedString returns the response compressed and base64 encoded
func (resp *Response) CompressedEncodedString() (string, error) {
	s, err := resp.String()
	if err != nil {
		return "", err
	}
	compressed := util.Compress([]byte(s))
	return base64.StdEncoding.EncodeToString(compressed), nil
}

// ValidateSignature checks signed elements in the response.
// There may be a signature on the Response element, Assertion element, or both.
// At least one signature must be present and all signatures must be valid.
func (resp *Response) ValidateSignature(certs []*x509.Certificate) error {
	// if this is a parsed response the signatures will be missing
	// so we have to use the original xml
	if resp.originalString != "" {
		return ValidateResponseSignature(resp.originalString, certs)
	}
	foundSignature := false
	if resp.Signature != nil {
		if err := xmldsig.VerifySignature(resp.Element(), certs); err != nil {
			return fmt.Errorf("signature invalid for Response element: %w", err)
		}
		foundSignature = true
	}
	if resp.Assertion.Signature != nil {
		if err := xmldsig.VerifySignature(resp.Assertion.Element(), certs); err != nil {
			return fmt.Errorf("signature invalid for Assertion element: %w", err)
		}
		foundSignature = true
	}
	if !foundSignature {
		return errors.New("signature not found in Response or Assertion")
	}
	return nil
}

// ValidateResponseSignature checks signed elements in a Response XML document.
// There may be a signature in the Response element, Assertion element, or both.
// At least one signature must be present and all signatures must be valid.
func ValidateResponseSignature(rawXML string, certs []*x509.Certificate) error {
	foundSignature := false

	doc := etree.NewDocument()
	err := doc.ReadFromString(rawXML)
	if err != nil {
		return err
	}

	root := doc.Root()
	if root == nil {
		return errors.New("root element not found")
	}
	if root.Tag != "Response" {
		return fmt.Errorf("root element is not Response, found %s instead", root.Tag)
	}

	for _, rootChild := range root.ChildElements() {
		if rootChild.Tag == "Signature" {
			if err := xmldsig.VerifySignature(root, certs); err != nil {
				return fmt.Errorf("signature invalid for Response element: %w", err)
			}
			foundSignature = true
		}
		if rootChild.Tag == "Assertion" {
			for _, assertionChild := range rootChild.ChildElements() {
				if assertionChild.Tag == "Signature" {
					if err := xmldsig.VerifySignature(rootChild, certs); err != nil {
						return fmt.Errorf("signature invalid for Assertion element: %w", err)
					}
					foundSignature = true
				}
			}
		}
	}

	if !foundSignature {
		return errors.New("signature not found in Response or Assertion")
	}
	return nil
}
