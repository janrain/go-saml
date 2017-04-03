package saml

import (
	"encoding/base64"
	"encoding/xml"
	"errors"
	"time"

	"github.com/janrain/go-saml/util"
)

const (
	xmlResponseID          = "urn:oasis:names:tc:SAML:2.0:protocol:Response"
	xmlResponseAssertionID = "Assertion"
)

func decodeResponse(rawResponse string, compressed bool) (*Response, error) {
	decodedResponse, err := base64.StdEncoding.DecodeString(rawResponse)
	if err != nil {
		return nil, err
	}

	if compressed {
		decodedResponse = util.Decompress(decodedResponse)
	}

	resp := Response{}
	err = xml.Unmarshal(decodedResponse, &resp)
	if err != nil {
		return nil, err
	}

	// There is a bug with XML namespaces in Go that's causing XML attributes with colons to not be roundtrip
	// marshal and unmarshaled so we'll keep the original string around for validation.
	resp.originalString = string(decodedResponse)
	return &resp, nil
}

// ParseCompressedEncodedResponse decodes, decompresses and parses a SAML Response
func ParseCompressedEncodedResponse(b64ResponseXML string) (*Response, error) {
	return decodeResponse(b64ResponseXML, true)
}

// ParseCompressedEncodedResponse decodes, and parses a SAML Response
func ParseEncodedResponse(b64ResponseXML string) (*Response, error) {
	return decodeResponse(b64ResponseXML, false)
}

// NewResponse constructs a Response
func NewResponse() *Response {
	id := util.ID()
	return &Response{
		XMLName: xml.Name{
			Local: "samlp:Response",
		},
		SAMLP:        "urn:oasis:names:tc:SAML:2.0:protocol",
		SAML:         "urn:oasis:names:tc:SAML:2.0:assertion",
		SAMLSIG:      "http://www.w3.org/2000/09/xmldsig#",
		ID:           id,
		Version:      "2.0",
		IssueInstant: time.Now().UTC().Format(time.RFC3339Nano),
		Issuer: Issuer{
			XMLName: xml.Name{
				Local: "saml:Issuer",
			},
			Url: "", // caller must populate ar.AppSettings.AssertionConsumerServiceURL,
		},
		Signature: Signature{
			XMLName: xml.Name{
				Local: "samlsig:Signature",
			},
			Id: "Signature1",
			SignedInfo: SignedInfo{
				XMLName: xml.Name{
					Local: "samlsig:SignedInfo",
				},
				CanonicalizationMethod: CanonicalizationMethod{
					XMLName: xml.Name{
						Local: "samlsig:CanonicalizationMethod",
					},
					Algorithm: "http://www.w3.org/2001/10/xml-exc-c14n#",
				},
				SignatureMethod: SignatureMethod{
					XMLName: xml.Name{
						Local: "samlsig:SignatureMethod",
					},
					Algorithm: "http://www.w3.org/2000/09/xmldsig#rsa-sha1",
				},
				SamlsigReference: SamlsigReference{
					XMLName: xml.Name{
						Local: "samlsig:Reference",
					},
					URI: "#" + id,
					Transforms: Transforms{
						XMLName: xml.Name{
							Local: "samlsig:Transforms",
						},
						Transform: Transform{
							XMLName: xml.Name{
								Local: "samlsig:Transform",
							},
							Algorithm: "http://www.w3.org/2000/09/xmldsig#enveloped-signature",
						},
					},
					DigestMethod: DigestMethod{
						XMLName: xml.Name{
							Local: "samlsig:DigestMethod",
						},
						Algorithm: "http://www.w3.org/2000/09/xmldsig#sha1",
					},
					DigestValue: DigestValue{
						XMLName: xml.Name{
							Local: "samlsig:DigestValue",
						},
					},
				},
			},
			SignatureValue: SignatureValue{
				XMLName: xml.Name{
					Local: "samlsig:SignatureValue",
				},
			},
			KeyInfo: KeyInfo{
				XMLName: xml.Name{
					Local: "samlsig:KeyInfo",
				},
				X509Data: X509Data{
					XMLName: xml.Name{
						Local: "samlsig:X509Data",
					},
					X509Certificate: X509Certificate{
						XMLName: xml.Name{
							Local: "samlsig:X509Certificate",
						},
						Cert: "", // caller must populate cert,
					},
				},
			},
		},
		Status: Status{
			XMLName: xml.Name{
				Local: "samlp:Status",
			},
			StatusCode: StatusCode{
				XMLName: xml.Name{
					Local: "samlp:StatusCode",
				},
				// TODO unsuccesful responses??
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
			IssueInstant: time.Now().UTC().Format(time.RFC3339Nano),
			Issuer: Issuer{
				XMLName: xml.Name{
					Local: "saml:Issuer",
				},
				Url: "", // caller must populate ar.AppSettings.AssertionConsumerServiceURL,
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
					Value:  "",
				},
				SubjectConfirmation: SubjectConfirmation{
					XMLName: xml.Name{
						Local: "saml:SubjectConfirmation",
					},
					Method: "urn:oasis:names:tc:SAML:2.0:cm:bearer",
					SubjectConfirmationData: SubjectConfirmationData{
						InResponseTo: "",
						NotOnOrAfter: time.Now().Add(time.Minute * 5).UTC().Format(time.RFC3339Nano),
						Recipient:    "",
					},
				},
			},
			Conditions: Conditions{
				XMLName: xml.Name{
					Local: "saml:Conditions",
				},
				NotBefore:    time.Now().Add(time.Minute * -5).UTC().Format(time.RFC3339Nano),
				NotOnOrAfter: time.Now().Add(time.Minute * 5).UTC().Format(time.RFC3339Nano),
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

// Validate validates the Response
func (r *Response) Validate(s *ServiceProviderSettings) error {
	if r.Version != "2.0" {
		return errors.New("unsupported SAML Version")
	}

	if len(r.ID) == 0 {
		return errors.New("missing ID attribute on SAML Response")
	}

	if len(r.Assertion.ID) == 0 {
		return errors.New("no Assertions")
	}

	if r.Destination != s.AssertionConsumerServiceURL {
		return errors.New("destination mismath expected: " + s.AssertionConsumerServiceURL + " not " + r.Destination)
	}

	if r.Assertion.Subject.SubjectConfirmation.Method != "urn:oasis:names:tc:SAML:2.0:cm:bearer" {
		return errors.New("assertion method exception")
	}

	if r.Assertion.Subject.SubjectConfirmation.SubjectConfirmationData.Recipient != s.AssertionConsumerServiceURL {
		return errors.New("subject recipient mismatch, expected: " + s.AssertionConsumerServiceURL + " not " + r.Assertion.Subject.SubjectConfirmation.SubjectConfirmationData.Recipient)
	}

	expires := r.Assertion.Subject.SubjectConfirmation.SubjectConfirmationData.NotOnOrAfter
	notOnOrAfter, e := time.Parse(time.RFC3339, expires)
	if e != nil {
		return e
	}
	if notOnOrAfter.Before(time.Now()) {
		return errors.New("assertion has expired on: " + expires)
	}

	attributeID := ""
	if len(r.Signature.SignatureValue.Value) > 0 {
		attributeID = xmlResponseID
	} else if len(r.Assertion.Signature.SignatureValue.Value) > 0 {
		attributeID = xmlResponseAssertionID
	}

	if attributeID == "" {
		return errors.New("no signature found")
	}

	err := VerifySignature(r.originalString, s.IDPPublicCertPath, attributeID)
	if err != nil {
		return err
	}

	return nil
}

// String returns the stringified response
func (r *Response) String() (string, error) {
	b, err := xml.MarshalIndent(r, "", "    ")
	if err != nil {
		return "", err
	}

	return string(b), nil
}

// SignedString returns the signed, stringified response
func (r *Response) SignedString(privateKeyPath string) (string, error) {
	s, err := r.String()
	if err != nil {
		return "", err
	}

	return Sign(s, privateKeyPath, xmlRequestID)
}

// EncodedSignedString returns the signed, stringified response base64 encoded
func (r *Response) EncodedSignedString(privateKeyPath string) (string, error) {
	signed, err := r.SignedString(privateKeyPath)
	if err != nil {
		return "", err
	}
	b64XML := base64.StdEncoding.EncodeToString([]byte(signed))
	return b64XML, nil
}

// EncodedSignedString returns the signed, stringified response compressed with
// the deflate algorithm and base64 encoded
func (r *Response) CompressedEncodedSignedString(privateKeyPath string) (string, error) {
	signed, err := r.SignedString(privateKeyPath)
	if err != nil {
		return "", err
	}
	compressed := util.Compress([]byte(signed))
	b64XML := base64.StdEncoding.EncodeToString(compressed)
	return b64XML, nil
}

// GetAttribute finds an attribute by Name or FriendlyName and returns
// the first value, or a blank string if not found
func (r *Response) GetAttribute(name string) string {
	for _, attr := range r.Assertion.AttributeStatement.Attributes {
		if attr.Name == name || attr.FriendlyName == name {
			return attr.AttributeValues[0].Value
		}
	}
	return ""
}

// GetAttributeValues finds an attribute by Name or FriendlyName and returns
// all values as a list
func (r *Response) GetAttributeValues(name string) []string {
	var values []string
	for _, attr := range r.Assertion.AttributeStatement.Attributes {
		if attr.Name == name || attr.FriendlyName == name {
			for _, v := range attr.AttributeValues {
				values = append(values, v.Value)
			}
		}
	}
	return values
}
