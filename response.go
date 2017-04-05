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
func (sp *ServiceProvider) ParseResponse(encodedXML string) (*Response, error) {
	decodedXML, err := base64.StdEncoding.DecodeString(encodedXML)
	if err != nil {
		return nil, err
	}

	if sp.UseCompression {
		decodedXML = util.Decompress(decodedXML)
	}

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

	// check for signature at top level and Assertion level
	attributeID := ""
	if len(resp.Signature.SignatureValue.Value) > 0 {
		attributeID = ResponseXMLID
	} else if len(resp.Assertion.Signature.SignatureValue.Value) > 0 {
		attributeID = ResponseAssertionXMLID
	}

	if attributeID == "" {
		return errors.New("no signature found")
	}

	err = xmlsec.VerifySignature(resp.originalString, sp.IDPPublicCertPath, attributeID)
	if err != nil {
		return err
	}

	return nil
}
