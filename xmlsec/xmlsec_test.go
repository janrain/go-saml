package xmlsec_test

import (
	"encoding/xml"
	"testing"

	"github.com/janrain/go-saml/xmlsec"

	"github.com/stretchr/testify/assert"
)

type TestXML struct {
	ID        string `xml:",attr"`
	Signature struct {
		Xmlns      string `xml:"xmlns,attr"`
		SignedInfo struct {
			CanonicalizationMethod struct {
				Algorithm string `xml:",attr"`
			}
			SignatureMethod struct {
				Algorithm string `xml:",attr"`
			}
			Reference struct {
				URI        string `xml:",attr"`
				Transforms struct {
					Transform struct {
						Algorithm string `xml:",attr"`
					}
				}
				DigestMethod struct {
					Algorithm string `xml:",attr"`
				}
				DigestValue string
			}
		}
		SignatureValue string
	}
}

func NewTestXML() TestXML {
	x := TestXML{}
	x.ID = "abc"
	x.Signature.Xmlns = "http://www.w3.org/2000/09/xmldsig#"
	x.Signature.SignedInfo.CanonicalizationMethod.Algorithm = "http://www.w3.org/2001/10/xml-exc-c14n#"
	x.Signature.SignedInfo.SignatureMethod.Algorithm = "http://www.w3.org/2000/09/xmldsig#rsa-sha1"
	x.Signature.SignedInfo.Reference.URI = "#abc"
	x.Signature.SignedInfo.Reference.DigestMethod.Algorithm = "http://www.w3.org/2000/09/xmldsig#sha1"
	x.Signature.SignedInfo.Reference.Transforms.Transform.Algorithm = "http://www.w3.org/2000/09/xmldsig#enveloped-signature"
	return x
}

func TestSignAndVerifyXML(t *testing.T) {
	assert := assert.New(t)
	x := NewTestXML()
	b, err := xml.MarshalIndent(x, "", "  ")
	assert.NoError(err)

	signed, err := xmlsec.Sign(string(b), "./testdata/default.key", "TestXML")
	assert.NoError(err)
	assert.NotEmpty(signed)

	err = xmlsec.VerifySignature(signed, "./testdata/default.crt", nil, "TestXML")
	assert.NoError(err)
}
