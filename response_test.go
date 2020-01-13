package saml_test

import (
	"crypto/rsa"
	"crypto/x509"
	"testing"

	"github.com/janrain/go-saml"
	"github.com/janrain/go-saml/testutil"

	"github.com/stretchr/testify/suite"
)

const (
	respIssuer      = "http://idp.test/auth"
	respDestination = "http://sp.test/callback"
	respAudience    = "http://sp.test"
	respSubject     = "someidentifier"
	respAttrName    = "Email"
	respAttrValue   = "test@test.test"
)

type ResponseSuite struct {
	suite.Suite
	privateKey *rsa.PrivateKey
	publicCert *x509.Certificate
	resp       *saml.Response
}

func (s *ResponseSuite) SetupSuite() {
	s.privateKey, s.publicCert = testutil.TestKeyPair()
}

func (s *ResponseSuite) SetupTest() {
	s.resp = saml.NewResponse(respIssuer, respAudience, respDestination, respSubject)
	s.resp.AddAttribute(respAttrName, respAttrValue)
}

func (s *ResponseSuite) ValidateResponse(resp *saml.Response, signed bool) {
	s.Equal(respIssuer, resp.Issuer.Value)
	s.Equal(respIssuer, resp.Assertion.Issuer.Value)
	s.Equal(respDestination, resp.Destination)
	s.Equal(respDestination, resp.Assertion.Subject.SubjectConfirmation.SubjectConfirmationData.Recipient)
	s.Equal(respAudience, resp.Assertion.Conditions.AudienceRestriction.Audience.Value)
	s.Equal(respAttrName, resp.Assertion.AttributeStatement.Attributes[0].Name)
	s.Equal(respAttrValue, resp.Assertion.AttributeStatement.Attributes[0].AttributeValues[0].Value)

	if signed {
		err := resp.ValidateSignature([]*x509.Certificate{s.publicCert})
		s.NoError(err)
	}
}

func (s *ResponseSuite) TestSignedAssertion() {
	err := s.resp.SignAssertion(s.privateKey, s.publicCert)
	s.NoError(err)
	s.NotNil(s.resp.Assertion.Signature)

	s.ValidateResponse(s.resp, true)

	out, err := s.resp.String()
	s.NoError(err)

	parsedResp, err := saml.ParseResponse(out)
	s.NoError(err)

	s.ValidateResponse(parsedResp, true)
}

func (s *ResponseSuite) TestSignedResponse() {
	err := s.resp.SignResponse(s.privateKey, s.publicCert)
	s.NoError(err)
	s.NotNil(s.resp.Signature)

	s.ValidateResponse(s.resp, true)

	out, err := s.resp.String()
	s.NoError(err)

	parsedResp, err := saml.ParseResponse(out)
	s.NoError(err)

	s.ValidateResponse(parsedResp, true)
}

func (s *ResponseSuite) TestSignedResponseAndAssertion() {
	err := s.resp.SignAssertion(s.privateKey, s.publicCert)
	s.NoError(err)

	err = s.resp.SignResponse(s.privateKey, s.publicCert)
	s.NoError(err)

	s.ValidateResponse(s.resp, true)

	out, err := s.resp.String()
	s.NoError(err)

	parsedResp, err := saml.ParseResponse(out)
	s.NoError(err)

	s.ValidateResponse(parsedResp, true)
}

func (s *ResponseSuite) TestEncoded() {
	out, err := s.resp.EncodedString()
	s.NoError(err)

	parsedResp, err := saml.ParseEncodedResponse(out)
	s.NoError(err)

	s.ValidateResponse(parsedResp, false)
}

func (s *ResponseSuite) TestCompressedEncoded() {
	out, err := s.resp.CompressedEncodedString()
	s.NoError(err)

	parsedResp, err := saml.ParseEncodedResponse(out)
	s.NoError(err)

	s.ValidateResponse(parsedResp, false)
}

func TestResponseSuite(t *testing.T) {
	suite.Run(t, &ResponseSuite{})
}
