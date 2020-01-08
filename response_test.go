package saml_test

import (
	"crypto/rsa"
	"crypto/x509"
	"testing"

	"github.com/janrain/go-saml"
	"github.com/janrain/go-saml/util"

	"github.com/stretchr/testify/suite"
)

const (
	respIssuer      = "http://localhost"
	respDestination = "http://sp.test/acs"
	respAudience    = "http://sp.test"
	respSubject     = "someidentifier"
	respAttrName    = "Email"
	respAttrValue   = "test@test.test"
	respXPath       = "/Response/Assertion"
)

type ResponseSuite struct {
	suite.Suite
	privateKey *rsa.PrivateKey
	publicCert *x509.Certificate
	resp       *saml.Response
}

func (s *ResponseSuite) SetupSuite() {
	s.privateKey, s.publicCert = util.TestKeyPair()
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
		err := resp.VerifySignature(respXPath, []*x509.Certificate{s.publicCert})
		s.NoError(err)
	}
}

func (s *ResponseSuite) TestSignedString() {
	x, err := s.resp.SignedString(respXPath, s.privateKey, s.publicCert)
	s.NoError(err)

	parsedResp, err := saml.ParseResponse(x)
	s.NoError(err)

	s.ValidateResponse(parsedResp, true)
}

func (s *ResponseSuite) TestEncodedString() {
	x, err := s.resp.EncodedString()
	s.NoError(err)

	parsedResp, err := saml.ParseEncodedResponse(x)
	s.NoError(err)

	s.ValidateResponse(parsedResp, false)
}

func (s *ResponseSuite) TestCompressedEncodedString() {
	x, err := s.resp.CompressedEncodedString()
	s.NoError(err)

	parsedResp, err := saml.ParseEncodedResponse(x)
	s.NoError(err)

	s.ValidateResponse(parsedResp, false)
}

func (s *ResponseSuite) TestCompressedEncodedSignedString() {
	x, err := s.resp.CompressedEncodedSignedString(respXPath, s.privateKey, s.publicCert)
	s.NoError(err)

	parsedResp, err := saml.ParseEncodedResponse(x)
	s.NoError(err)

	s.ValidateResponse(parsedResp, true)
}

func TestResponseSuite(t *testing.T) {
	suite.Run(t, &ResponseSuite{})
}
