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
		XMLName: xml.Name{
			Local: "samlp:Response",
		},
		SAMLP:        "urn:oasis:names:tc:SAML:2.0:protocol",
		ID:           util.ID(),
		Version:      "2.0",
		IssueInstant: now.Format(time.RFC3339Nano),
		Issuer: Issuer{
			XMLName: xml.Name{
				Local: "saml:Issuer",
			},
			SAML:  "urn:oasis:names:tc:SAML:2.0:assertion",
			Value: issuer,
		},
		Destination: destination,
		Status: Status{
			XMLName: xml.Name{
				Local: "samlp:Status",
			},
			StatusCode: StatusCode{
				XMLName: xml.Name{
					Local: "samlp:StatusCode",
				},
				Value: "urn:oasis:names:tc:SAML:2.0:status:Success",
			},
		},
		Assertion: Assertion{
			XMLName: xml.Name{
				Local: "saml:Assertion",
			},
			XS:           "http://www.w3.org/2001/XMLSchema",
			XSI:          "http://www.w3.org/2001/XMLSchema-instance",
			SAML:         "urn:oasis:names:tc:SAML:2.0:assertion",
			Version:      "2.0",
			ID:           util.ID(),
			IssueInstant: now.Format(time.RFC3339Nano),
			Issuer: Issuer{
				XMLName: xml.Name{
					Local: "saml:Issuer",
				},
				Value: issuer,
			},
			Subject: Subject{
				XMLName: xml.Name{
					Local: "saml:Subject",
				},
				NameID: NameID{
					XMLName: xml.Name{
						Local: "saml:NameID",
					},
					Format: "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified",
					Value:  subject,
				},
				SubjectConfirmation: SubjectConfirmation{
					XMLName: xml.Name{
						Local: "saml:SubjectConfirmation",
					},
					Method: "urn:oasis:names:tc:SAML:2.0:cm:bearer",
					SubjectConfirmationData: SubjectConfirmationData{
						XMLName: xml.Name{
							Local: "saml:SubjectConfirmationData",
						},
						NotOnOrAfter: now.Add(time.Minute * 5).Format(time.RFC3339Nano),
						Recipient:    destination,
					},
				},
			},
			Conditions: Conditions{
				XMLName: xml.Name{
					Local: "saml:Conditions",
				},
				NotBefore:    now.Add(time.Minute * -5).Format(time.RFC3339Nano),
				NotOnOrAfter: now.Add(time.Minute * 5).Format(time.RFC3339Nano),
				AudienceRestriction: AudienceRestriction{
					XMLName: xml.Name{
						Local: "saml:AudienceRestriction",
					},
					Audience: Audience{
						XMLName: xml.Name{
							Local: "saml:Audience",
						},
						Value: audience,
					},
				},
			},
			AttributeStatement: AttributeStatement{
				XMLName: xml.Name{
					Local: "saml:AttributeStatement",
				},
				Attributes: []Attribute{},
			},
		},
	}
}

// AddAttribute adds an attribute to the response assertion
func (resp *Response) AddAttribute(name, value string) {
	resp.Assertion.AttributeStatement.Attributes = append(resp.Assertion.AttributeStatement.Attributes, Attribute{
		XMLName: xml.Name{
			Local: "saml:Attribute",
		},
		Name:       name,
		NameFormat: "urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified",
		AttributeValues: []AttributeValue{
			{
				XMLName: xml.Name{
					Local: "saml:AttributeValue",
				},
				Type:  "xs:string",
				Value: value,
			},
		},
	})
}

// String returns the response as a string
func (resp *Response) String() (string, error) {
	b, err := xml.MarshalIndent(resp, "", "    ")
	if err != nil {
		return "", fmt.Errorf("failed to marshal xml: %w", err)
	}

	return string(b), nil
}

// SignedString returns the response as a string with signature included
func (resp *Response) SignedString(xPath string, privateKey *rsa.PrivateKey, publicCert *x509.Certificate) (string, error) {
	s, err := resp.String()
	if err != nil {
		return "", err
	}

	return xmldsig.Sign(s, xPath, privateKey, publicCert)
}

// EncodedSignedString returns the response base64 encoded and signed
func (resp *Response) EncodedSignedString(xPath string, privateKey *rsa.PrivateKey, publicCert *x509.Certificate) (string, error) {
	signed, err := resp.SignedString(xPath, privateKey, publicCert)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString([]byte(signed)), nil
}

// CompressedEncodedSignedString returns the response compressed, base64 encoded, and signed
func (resp *Response) CompressedEncodedSignedString(xPath string, privateKey *rsa.PrivateKey, publicCert *x509.Certificate) (string, error) {
	signed, err := resp.SignedString(xPath, privateKey, publicCert)
	if err != nil {
		return "", err
	}
	compressed := util.Compress([]byte(signed))
	return base64.StdEncoding.EncodeToString(compressed), nil
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

// VerifySignature verifies the signature
func (resp *Response) VerifySignature(xPath string, certs []*x509.Certificate) error {
	return xmldsig.VerifySignature(resp.originalString, xPath, certs)
}
