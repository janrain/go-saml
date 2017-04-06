package saml

import (
	"encoding/base64"
	"encoding/xml"
	"errors"
	"time"

	"github.com/janrain/go-saml/util"
	"github.com/janrain/go-saml/xmlsec"
)

const (
	ResponseXMLID          = "urn:oasis:names:tc:SAML:2.0:protocol:Response"
	ResponseAssertionXMLID = "Assertion"
)

// ParseResponse decodes a SAML Response
func ParseResponse(encodedXML string) (*Response, error) {
	decodedXML, err := base64.StdEncoding.DecodeString(encodedXML)
	if err != nil {
		return nil, err
	}

	decompressedXML, err := util.Decompress(decodedXML)
	if err == nil {
		decodedXML = decompressedXML
	}
	// if there was an error during decompression, assume it wasn't compressed

	resp := &Response{}
	err = xml.Unmarshal(decodedXML, resp)
	if err != nil {
		return nil, err
	}

	// There is a bug with XML namespaces in Go that's causing them to not be roundtrip
	// marshal and unmarshaled so we'll keep the original string around for validation.
	resp.originalString = string(decodedXML)
	return resp, nil
}

// ValidateResponse validates a Response
func (sp *ServiceProvider) ValidateResponse(resp *Response) error {
	if resp.Version != "2.0" {
		return errors.New("unsupported SAML Version")
	}

	if len(resp.ID) == 0 {
		return errors.New("missing ID attribute on SAML Response")
	}

	if len(resp.Assertion.ID) == 0 {
		return errors.New("no Assertions")
	}

	if resp.Destination != sp.AssertionConsumerServiceURL {
		return errors.New("destination mismatch, expected: " + sp.AssertionConsumerServiceURL + " not " + resp.Destination)
	}

	if resp.Assertion.Subject.SubjectConfirmation.Method != "urn:oasis:names:tc:SAML:2.0:cm:bearer" {
		return errors.New("assertion method exception")
	}

	if resp.Assertion.Subject.SubjectConfirmation.SubjectConfirmationData.Recipient != sp.AssertionConsumerServiceURL {
		return errors.New("subject recipient mismatch, expected: " + sp.AssertionConsumerServiceURL + " not " + resp.Assertion.Subject.SubjectConfirmation.SubjectConfirmationData.Recipient)
	}

	expires := resp.Assertion.Subject.SubjectConfirmation.SubjectConfirmationData.NotOnOrAfter
	notOnOrAfter, err := time.Parse(time.RFC3339, expires)
	if err != nil {
		return err
	}
	if notOnOrAfter.Before(time.Now()) {
		return errors.New("assertion has expired on: " + expires)
	}

	// check for signature in root then Assertion
	attributeID := ""
	if len(resp.Signature.SignatureValue.Value) > 0 {
		attributeID = ResponseXMLID
	} else if len(resp.Assertion.Signature.SignatureValue.Value) > 0 {
		attributeID = ResponseAssertionXMLID
	}

	if attributeID == "" {
		return errors.New("no signature found")
	}

	// only checks the first signature found
	err = xmlsec.VerifySignature(resp.originalString, sp.IDPPublicCertPath, attributeID)
	if err != nil {
		return err
	}

	return nil
}

func NewResponse() *Response {
	return &Response{
		XMLName: xml.Name{
			Local: "samlp:Response",
		},
		SAMLP:        "urn:oasis:names:tc:SAML:2.0:protocol",
		SAML:         "urn:oasis:names:tc:SAML:2.0:assertion",
		SAMLSIG:      "http://www.w3.org/2000/09/xmldsig#",
		ID:           util.ID(),
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
					URI: "", // caller must populate "#" + ar.Id,
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

// AddAttribute add attribute to the Response
func (resp *Response) AddAttribute(name, value string) {
	resp.Assertion.AttributeStatement.Attributes = append(resp.Assertion.AttributeStatement.Attributes, Attribute{
		XMLName: xml.Name{
			Local: "saml:Attribute",
		},
		Name:       name,
		NameFormat: "urn:oasis:names:tc:SAML:2.0:attrname-format:basic",
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

func (resp *Response) String() (string, error) {
	b, err := xml.MarshalIndent(resp, "", "    ")
	if err != nil {
		return "", err
	}

	return string(b), nil
}

func (resp *Response) SignedString(privateKeyPath string) (string, error) {
	s, err := resp.String()
	if err != nil {
		return "", err
	}

	return xmlsec.Sign(s, privateKeyPath, ResponseXMLID)
}

func (resp *Response) EncodedSignedString(privateKeyPath string) (string, error) {
	signed, err := resp.SignedString(privateKeyPath)
	if err != nil {
		return "", err
	}
	b64XML := base64.StdEncoding.EncodeToString([]byte(signed))
	return b64XML, nil
}

func (resp *Response) CompressedEncodedSignedString(privateKeyPath string) (string, error) {
	signed, err := resp.SignedString(privateKeyPath)
	if err != nil {
		return "", err
	}
	compressed := util.Compress([]byte(signed))
	b64XML := base64.StdEncoding.EncodeToString(compressed)
	return b64XML, nil
}
