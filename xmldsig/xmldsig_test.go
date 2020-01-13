package xmldsig_test

import (
	"crypto/rsa"
	"crypto/x509"
	"testing"

	"github.com/janrain/go-saml/testutil"
	"github.com/janrain/go-saml/xmldsig"

	"github.com/beevik/etree"
	"github.com/stretchr/testify/suite"
)

const xmlDoc = `<samlp:Response Destination="http://localhost:8080/callback" ID="abc-response" InResponseTo="xyz" IssueInstant="2000-01-23T00:00:00.000Z" Version="2.0" xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol">
    <saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="abc-assertion" IssueInstant="2000-01-23T00:00:00.000Z" Version="2.0">
        <saml:Subject>
            <saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified">myuserid</saml:NameID>
            <saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
                <saml:SubjectConfirmationData InResponseTo="xyz" NotOnOrAfter="2050-01-23T00:00:00.000Z" Recipient="http://localhost:8080/callback"/>
            </saml:SubjectConfirmation>
        </saml:Subject>
        <saml:AttributeStatement>
            <saml:Attribute FriendlyName="" Name="Email" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified">
                <saml:AttributeValue xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="xs:string">test@test.test</saml:AttributeValue>
            </saml:Attribute>
        </saml:AttributeStatement>
    <ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:SignedInfo><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/><ds:SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/><ds:Reference URI="#abc-assertion"><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/><ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/></ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/><ds:DigestValue>z+Vt3uSMLiSqRNWJWsvjFjVpn0I=</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue>Z6qdROrZCJVO86TZPNXobLlHjyE11vszK4g97s/Hz+Q0brpMXVIH5rznRQ9gxkB6sZpDnd8RCafc8xjihnTJ/m9lMacDlzaKi0pGqz9XKDD2JqoMyQdsMApt6bEOeoQ2W0ScyH1FnO786pD5J0n92sYbc1HO7MHiw9zoY2kDOcNcpqSCSmCIkezqc9o5vV4OLKJRCQPOTwPcsT6buspe84AUXo3bqLdaIdo3PzqAt70Cf6pVEkf7bnXO03hoikyorRrHxI3n7/drOHc1ZC2rbVcbARrtAc6J0aDlcOtc0GTLZlWr4kTlUZyxVPuJ46kxOgAh2scnsdAiZzVXZaZZMsH0ttvlZyapxFVjuFheU2bxXDeeQTh29VEikJg/sP1zzqhD3mPjNc+imQwgrTPV1jwrnRq082i9QamDDQw8EPpXOZCCO18/I64y2GP9FlnoY+OuUlHGU8RipfKHgaFvYtGdiwFDQXEHUpct+VphV9E7hX10UkhCl95uQCiZJOTaqzKpKsR9OG7CewzRrNCM1+aOTbRf/wtuiOQ6C8Dcyqe11LL5RfCuBAHK1DXq91TI3+tpkxYo8j4oR/FXCPHBr1SRGBvfagSjViMGJDdtF4Bw9Nw/2YJfHUxNGqhLZL0PNwIgipW/10gXo9cE+hgk5E+/cMCNz3YWq7sEzgIOLso=</ds:SignatureValue><ds:KeyInfo><ds:X509Data><ds:X509Certificate>MIIFYTCCA0mgAwIBAgIJAI1a1evtQYDkMA0GCSqGSIb3DQEBBQUAME8xCzAJBgNVBAYTAkZSMQ4wDAYDVQQHEwVQYXJpczEOMAwGA1UEChMFRWtpbm8xDzANBgNVBAsTBkRldk9wczEPMA0GA1UEAxMGZ29zYW1sMB4XDTE1MDcyMDIyNDE1OFoXDTI1MDcxNzIyNDE1OFowTzELMAkGA1UEBhMCRlIxDjAMBgNVBAcTBVBhcmlzMQ4wDAYDVQQKEwVFa2lubzEPMA0GA1UECxMGRGV2T3BzMQ8wDQYDVQQDEwZnb3NhbWwwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQDoo/DTqWoyJyXR0K+hF4pw4qBkaLL0gbbKoiKH+7wvdzHONOoFBfF5NQj02M4JJyeOQ6+hHYV4QjtUG41zMf1XoH/U6Ey/oURkuCJJCGhW9AyD+A4WP4YS4Ag/uN7o0P3nuj7hJipefY1Bzmg2n89iHDcpHvwKTtVWZYdj6Dgbwh9ZH9QiRRRp+GZHXu7nW+VCZM0mE+9qjxK4Mw+KEDD6LIgSOAzRLWLyUmb2Kwvc++DhwDtIoThVHYoNd4Sk9j6/4B3DmPa83i/1dZKyFaMCDUn7+i6KhwIWbGfg6uQMM8G6XzF4V5x5agmg8DK24VXs3yb1lOIUczNVq4ZHkApc4jwHWiXncab88UnDPG7pVm87whaMghWNwrYAt//QEInExkxjNhWwxNFlelg/8b9fUsdH58FeZiZ+mNnwACXnggmZEE+lUX5Fh8l79bke+dnQbJAhQfi+OhmNlqmc+ouKDPYqk0/IC9q/3Tg65Ej9Miq918IAvQAVtlwwwp6I5/02Aa5iqZozBTUXYqWE/qXixlpWh2tP5ljecgGazuw58tGj2+nXS9DA9wVgGUAl4xJFO/s8emna52lSPzwvcr6j+BMifXHr0WBIEcTbtzXhxUpfC6IC14yfPOf8g4WKKgg1Wq3H4dGiE11y66ceYeh1RZlWXq/JEtJ1FVLoGq4qLwIDAQABo0AwPjA8BgNVHREENTAzghBsb2dzLmV4YW1wbGUuY29tghNtZXRyaWNzLmV4YW1wbGUuY29thwTAqAABhwQKAAAyMA0GCSqGSIb3DQEBBQUAA4ICAQAcaLdziL6dNZ3lXtm3nsI9ceSVwp2yKfpsswjs524bOsLK97Ucf4hhlh1bq5hywWbm85N7iuxdpBuhSmeJ94ryFAPDUkhR1Mzcl48c6R8tPbJVhabhbfg+uIHi4BYUA0olesdsyTOsRHprM4iV+PlKZ85SQT04ZNyaqIDzmNEP7YXDl/Wl3Q0N5E1UyGfDTBxo07srqrAM2E5X7hN9bwdZX0Hbo/C4q3wgRHAts/wJXXWSSTe1jbIWYXemEkwAEd01BiMBj1LYK/sJ8s4fONdLxIyKqLUh1Ja46moqpgl5AHuPbqnwPdgGGvEdiBzz5ppHs0wXFopk+J4rzYRhya6a3BMXiDjg+YOSwFgCysmWmCrxoImmfcQWUZJy5eMow+hBBiKgT2DxggqVzReN3C7uwsFZLZCsv8+MjvFQz52oEp/GWqFepggFQiRIK7/QmwcsDdz6zBobZJaJstq3R2mHYkhaVUIOqEuqyD2N7qms8bek7xzq6F9KkYLkPK/d2Crkxq1bnvM7oO8IsA6vHdTexfZ1SRPf7Mxpg8DMV788qE09BDZ5mLFOkRbwFY7MHRX6Mz59gfnAcRwK/0HnG6c8EZCJH8jMStzqA0bUjzDiyN2ZgzFkTUA9Cr8jkq8grtVMsp40mjFnSg/FR+O+rG32D/rbfvNYFCR8wawOcYrGyA==</ds:X509Certificate></ds:X509Data></ds:KeyInfo></ds:Signature></saml:Assertion>
    <samlp:Status>
        <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
    </samlp:Status>
</samlp:Response>`

type XmldsigSuite struct {
	suite.Suite
	privateKey *rsa.PrivateKey
	publicCert *x509.Certificate
	element    *etree.Element
}

func (s *XmldsigSuite) SetupSuite() {
	s.privateKey, s.publicCert = testutil.TestKeyPair()
	doc := etree.NewDocument()
	err := doc.ReadFromString(xmlDoc)
	if err != nil {
		panic(err)
	}
	s.element = doc.Root().FindElement("/Response/Assertion")
}

func (s *XmldsigSuite) TestSign() {
	sig, err := xmldsig.Sign(s.element, s.privateKey, s.publicCert)
	s.NoError(err)
	s.NotEmpty(sig)
	s.Equal("Signature", sig.Tag)
}

func (s *XmldsigSuite) TestVerifySignature() {
	err := xmldsig.VerifySignature(s.element, []*x509.Certificate{s.publicCert})
	s.NoError(err)
}

func TestXmldsigSuite(t *testing.T) {
	suite.Run(t, &XmldsigSuite{})
}
