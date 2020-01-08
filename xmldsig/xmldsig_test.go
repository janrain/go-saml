package xmldsig_test

import (
	"crypto/rsa"
	"crypto/x509"
	"testing"

	"github.com/janrain/go-saml/util"
	"github.com/janrain/go-saml/xmldsig"

	"github.com/stretchr/testify/suite"
)

const xmlDoc = `<samlp:Response Destination="http://localhost:8080/callback" ID="abc-response" InResponseTo="xyz" IssueInstant="2000-01-23T00:00:00.000Z" Version="2.0" xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol">
    <samlp:Status>
        <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
    </samlp:Status>
    <saml:Assertion ID="abc-assertion" IssueInstant="2000-01-23T00:00:00.000Z" Version="2.0" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
        <saml:Subject>
            <saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified">myuserid</saml:NameID>
            <saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
                <saml:SubjectConfirmationData InResponseTo="xyz" NotOnOrAfter="2050-01-23T00:00:00.000Z" Recipient="http://localhost:8080/callback"/>
            </saml:SubjectConfirmation>
        </saml:Subject>
        <saml:AttributeStatement>
            <saml:Attribute FriendlyName="" Name="Email" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified">
                <saml:AttributeValue xsi:type="xs:string">test@test.test</saml:AttributeValue>
            </saml:Attribute>
        </saml:AttributeStatement>
    </saml:Assertion>
</samlp:Response>`

type XmldsigSuite struct {
	suite.Suite
	privateKey *rsa.PrivateKey
	publicCert *x509.Certificate
}

func (s *XmldsigSuite) SetupSuite() {
	s.privateKey, s.publicCert = util.TestKeyPair()
}

func (s *XmldsigSuite) TestSignAndVerify() {
	signedDoc, err := xmldsig.Sign(xmlDoc, "/Response/Assertion", s.privateKey, s.publicCert)
	s.NoError(err)

	err = xmldsig.VerifySignature(signedDoc, "/Response/Assertion", []*x509.Certificate{s.publicCert})
	s.NoError(err)
}

func TestXmldsigSuite(t *testing.T) {
	suite.Run(t, &XmldsigSuite{})
}
