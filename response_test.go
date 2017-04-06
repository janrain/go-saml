package saml_test

import (
	"encoding/base64"
	"testing"

	"github.com/janrain/go-saml"
	"github.com/janrain/go-saml/xmlsec"

	"github.com/stretchr/testify/suite"
)

const xmldoc = `<samlp:Response Destination="http://localhost:8080/callback" ID="abc-response" InResponseTo="xyz" IssueInstant="2000-01-23T00:00:00.000Z" Version="2.0" xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol">
  <Signature xmlns="http://www.w3.org/2000/09/xmldsig#">
    <SignedInfo>
      <CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
      <SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/>
      <Reference URI="#abc-response">
        <Transforms>
          <Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>
        </Transforms>
        <DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/>
        <DigestValue/>
      </Reference>
    </SignedInfo>
    <SignatureValue/>
    <KeyInfo>
      <X509Data/>
    </KeyInfo>
  </Signature>
  <samlp:Status>
    <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
  </samlp:Status>
  <saml:Assertion ID="abc-assertion" IssueInstant="2000-01-23T00:00:00.000Z" Version="2.0" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">
    <saml:Subject>
      <saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified">myuserid</saml:NameID>
      <saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
        <saml:SubjectConfirmationData InResponseTo="xyz" NotOnOrAfter="2050-01-23T00:00:00.000Z" Recipient="http://localhost:8080/callback"/>
      </saml:SubjectConfirmation>
    </saml:Subject>
  </saml:Assertion>
</samlp:Response>`

type ResponseTestSuite struct {
	suite.Suite
	sp *saml.ServiceProvider
}

func (s *ResponseTestSuite) SetupTest() {
	s.sp = &saml.ServiceProvider{
		PublicCertPath:              "./xmlsec/testdata/default.crt",
		PrivateKeyPath:              "./xmlsec/testdata/default.key",
		IDPSSOURL:                   "http://www.onelogin.net",
		IDPSSODescriptorURL:         "http://www.onelogin.net",
		IDPPublicCertPath:           "./xmlsec/testdata/default.crt",
		AssertionConsumerServiceURL: "http://localhost:8080/callback",
		SignRequest:                 true,
	}
	err := s.sp.Init()
	if err != nil {
		panic(err)
	}
}

func (s *ResponseTestSuite) TestParseAndValidateResponse() {
	signedXML, err := xmlsec.Sign(xmldoc, s.sp.PrivateKeyPath, saml.ResponseXMLID)
	s.NoError(err)

	encodedXML := base64.StdEncoding.EncodeToString([]byte(signedXML))
	resp, err := saml.ParseResponse(encodedXML)
	s.NoError(err)
	s.Equal(s.sp.AssertionConsumerServiceURL, resp.Destination)
	s.Equal("myuserid", resp.Assertion.Subject.NameID.Value)

	err = s.sp.ValidateResponse(resp)
	s.NoError(err)
}

func TestResponse(t *testing.T) {
	suite.Run(t, &ResponseTestSuite{})
}
