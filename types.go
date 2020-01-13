package saml

import (
	"encoding/xml"
	"strconv"

	"github.com/beevik/etree"
)

// AuthnRequest represents a SAML AuthnRequest
type AuthnRequest struct {
	XMLName xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:protocol AuthnRequest"`

	ID                             string `xml:",attr"`
	Version                        string `xml:",attr"`
	IssueInstant                   string `xml:",attr"`
	Destination                    string `xml:",attr"`
	Consent                        string `xml:",attr"`
	AssertionConsumerServiceURL    string `xml:",attr"`
	AssertionConsumerServiceIndex  string `xml:",attr"`
	AttributeConsumingServiceIndex string `xml:",attr"`
	ProtocolBinding                string `xml:",attr"`

	Issuer                *Issuer
	Signature             *etree.Element
	NameIDPolicy          *NameIDPolicy `xml:"urn:oasis:names:tc:SAML:2.0:protocol NameIDPolicy"`
	RequestedAuthnContext *RequestedAuthnContext

	originalString string
}

// Element returns AuthnRequest as etree.Element
func (r *AuthnRequest) Element() *etree.Element {
	e := etree.NewElement("samlp:AuthnRequest")
	e.CreateAttr("xmlns:saml", "urn:oasis:names:tc:SAML:2.0:assertion")
	e.CreateAttr("xmlns:samlp", "urn:oasis:names:tc:SAML:2.0:protocol")
	e.CreateAttr("ID", r.ID)
	e.CreateAttr("Version", r.Version)
	e.CreateAttr("IssueInstant", r.IssueInstant)
	if r.Destination != "" {
		e.CreateAttr("Destination", r.Destination)
	}
	if r.Consent != "" {
		e.CreateAttr("Consent", r.Consent)
	}
	if r.AssertionConsumerServiceURL != "" {
		e.CreateAttr("AssertionConsumerServiceURL", r.AssertionConsumerServiceURL)
	}
	if r.AssertionConsumerServiceIndex != "" {
		e.CreateAttr("AssertionConsumerServiceIndex", r.AssertionConsumerServiceIndex)
	}
	if r.ProtocolBinding != "" {
		e.CreateAttr("ProtocolBinding", r.ProtocolBinding)
	}
	if r.AttributeConsumingServiceIndex != "" {
		e.CreateAttr("AttributeConsumingServiceIndex", r.AttributeConsumingServiceIndex)
	}
	if r.Issuer != nil {
		e.AddChild(r.Issuer.Element())
	}
	if r.Signature != nil {
		e.AddChild(r.Signature)
	}
	if r.NameIDPolicy != nil {
		e.AddChild(r.NameIDPolicy.Element())
	}
	if r.RequestedAuthnContext != nil {
		e.AddChild(r.RequestedAuthnContext.Element())
	}
	return e
}

// Issuer represents a SAML Issuer
type Issuer struct {
	XMLName xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:assertion Issuer"`

	Format *string `xml:",attr"`
	Value  string  `xml:",chardata"`
}

// Element returns Issuer as etree.Element
func (r *Issuer) Element() *etree.Element {
	e := etree.NewElement("saml:Issuer")
	if r.Format != nil && *r.Format != "" {
		e.CreateAttr("Format", *r.Format)
	}
	e.SetText(r.Value)
	return e
}

// NameIDPolicy represents a SAML NameIDPolicy
type NameIDPolicy struct {
	XMLName xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:protocol NameIDPolicy"`

	AllowCreate *bool   `xml:",attr"`
	Format      *string `xml:",attr"`
}

// Element returns NameIDPolicy as etree.Element
func (r *NameIDPolicy) Element() *etree.Element {
	e := etree.NewElement("samlp:NameIDPolicy")
	if r.AllowCreate != nil {
		e.CreateAttr("AllowCreate", strconv.FormatBool(*r.AllowCreate))
	}
	if r.Format != nil && *r.Format != "" {
		e.CreateAttr("Format", *r.Format)
	}
	return e
}

// RequestedAuthnContext represents a SAML RequestedAuthnContext
type RequestedAuthnContext struct {
	XMLName xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:protocol RequestedAuthnContext"`

	Comparison           string `xml:",attr"`
	AuthnContextClassRef *AuthnContextClassRef
}

// Element returns RequestedAuthnContext as etree.Element
func (r *RequestedAuthnContext) Element() *etree.Element {
	e := etree.NewElement("samlp:RequestedAuthnContext")
	if r.Comparison != "" {
		e.CreateAttr("Comparison", r.Comparison)
	}
	if r.AuthnContextClassRef != nil {
		e.AddChild(r.AuthnContextClassRef.Element())
	}
	return e
}

// AuthnContextClassRef represents a SAML AuthnContextClassRef
type AuthnContextClassRef struct {
	XMLName xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:assertion AuthnContextClassRef"`

	Transport string `xml:",chardata"`
}

// Element returns AuthnContextClassRef as etree.Element
func (r *AuthnContextClassRef) Element() *etree.Element {
	e := etree.NewElement("saml:AuthnContextClassRef")
	e.SetText(r.Transport)
	return e
}

// Response represents a SAML Response
type Response struct {
	XMLName xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:protocol Response"`

	ID           string `xml:",attr"`
	Version      string `xml:",attr"`
	IssueInstant string `xml:",attr"`
	InResponseTo string `xml:",attr"`
	Destination  string `xml:",attr"`
	Consent      string `xml:",attr"`

	Issuer    *Issuer `xml:"urn:oasis:names:tc:SAML:2.0:assertion Issuer"`
	Signature *etree.Element
	Status    Status     `xml:"urn:oasis:names:tc:SAML:2.0:protocol Status"`
	Assertion *Assertion `xml:"urn:oasis:names:tc:SAML:2.0:assertion Assertion"`

	originalString string
}

// Element returns Response as etree.Element
func (r *Response) Element() *etree.Element {
	e := etree.NewElement("samlp:Response")
	e.CreateAttr("xmlns:saml", "urn:oasis:names:tc:SAML:2.0:assertion")
	e.CreateAttr("xmlns:samlp", "urn:oasis:names:tc:SAML:2.0:protocol")
	// Note: This namespace is not used by any element or attribute name, but
	// is required so that the AttributeValue type element can have a value like
	// "xs:string". If we don't declare it here, then it will be stripped by the
	// cannonicalizer. This could be avoided by providing a prefix list to the
	// cannonicalizer, but prefix lists do not appear to be implemented correctly
	// in some libraries, so the safest action is to always produce XML that is
	// (a) in canonical form and (b) does not require prefix lists.
	e.CreateAttr("xmlns:xs", "http://www.w3.org/2001/XMLSchema")
	e.CreateAttr("ID", r.ID)
	e.CreateAttr("Version", r.Version)
	e.CreateAttr("IssueInstant", r.IssueInstant)
	if r.InResponseTo != "" {
		e.CreateAttr("InResponseTo", r.InResponseTo)
	}
	if r.Destination != "" {
		e.CreateAttr("Destination", r.Destination)
	}
	if r.Consent != "" {
		e.CreateAttr("Consent", r.Consent)
	}
	if r.Issuer != nil {
		e.AddChild(r.Issuer.Element())
	}
	if r.Signature != nil {
		e.AddChild(r.Signature)
	}
	e.AddChild(r.Status.Element())
	if r.Assertion != nil {
		e.AddChild(r.Assertion.Element())
	}
	return e
}

// Status represents a SAML Status
type Status struct {
	XMLName xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:protocol Status"`

	StatusCode StatusCode `xml:"StatusCode"`
}

// Element returns Status as etree.Element
func (r *Status) Element() *etree.Element {
	e := etree.NewElement("samlp:Status")
	e.AddChild(r.StatusCode.Element())
	return e
}

// StatusCode represents a SAML StatusCode
type StatusCode struct {
	XMLName xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:protocol StatusCode"`
	Value   string   `xml:",attr"`
}

// Element returns StatusCode as etree.Element
func (r *StatusCode) Element() *etree.Element {
	e := etree.NewElement("samlp:StatusCode")
	e.CreateAttr("Value", r.Value)
	return e
}

// Assertion represents a SAML Assertion
type Assertion struct {
	XMLName xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:assertion Assertion"`

	ID           string `xml:",attr"`
	Version      string `xml:",attr"`
	IssueInstant string `xml:",attr"`

	Issuer             Issuer `xml:"urn:oasis:names:tc:SAML:2.0:assertion Issuer"`
	Signature          *etree.Element
	Subject            *Subject
	Conditions         *Conditions
	AttributeStatement *AttributeStatement
}

// Element returns Assertion as etree.Element
func (r *Assertion) Element() *etree.Element {
	e := etree.NewElement("saml:Assertion")
	e.CreateAttr("xmlns:saml", "urn:oasis:names:tc:SAML:2.0:assertion")
	e.CreateAttr("ID", r.ID)
	e.CreateAttr("Version", r.Version)
	e.CreateAttr("IssueInstant", r.IssueInstant)
	e.AddChild(r.Issuer.Element())
	if r.Signature != nil {
		e.AddChild(r.Signature)
	}
	if r.Subject != nil {
		e.AddChild(r.Subject.Element())
	}
	if r.Conditions != nil {
		e.AddChild(r.Conditions.Element())
	}
	if r.AttributeStatement != nil {
		e.AddChild(r.AttributeStatement.Element())
	}
	return e
}

// Conditions represents a SAML Conditions
type Conditions struct {
	NotBefore    string `xml:",attr"`
	NotOnOrAfter string `xml:",attr"`

	AudienceRestriction *AudienceRestriction
}

// Element returns Conditions as etree.Element
func (r *Conditions) Element() *etree.Element {
	e := etree.NewElement("saml:Conditions")
	if r.NotBefore != "" {
		e.CreateAttr("NotBefore", r.NotBefore)
	}
	if r.NotOnOrAfter != "" {
		e.CreateAttr("NotOnOrAfter", r.NotOnOrAfter)
	}
	if r.AudienceRestriction != nil {
		e.AddChild(r.AudienceRestriction.Element())
	}
	return e
}

// AudienceRestriction represents a SAML AudienceRestriction
type AudienceRestriction struct {
	Audience Audience
}

// Element returns AudienceRestriction as etree.Element
func (r *AudienceRestriction) Element() *etree.Element {
	e := etree.NewElement("saml:AudienceRestriction")
	e.AddChild(r.Audience.Element())
	return e
}

// Audience represents a SAML Audience
type Audience struct {
	Value string `xml:",chardata"`
}

// Element returns Audience as etree.Element
func (r *Audience) Element() *etree.Element {
	e := etree.NewElement("saml:Audience")
	e.SetText(r.Value)
	return e
}

// Subject represents a SAML Subject
type Subject struct {
	XMLName xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:assertion Subject"`

	NameID              *NameID
	SubjectConfirmation *SubjectConfirmation
}

// Element returns Subject as etree.Element
func (r *Subject) Element() *etree.Element {
	e := etree.NewElement("saml:Subject")
	if r.NameID != nil {
		e.AddChild(r.NameID.Element())
	}
	if r.SubjectConfirmation != nil {
		e.AddChild(r.SubjectConfirmation.Element())
	}
	return e
}

// SubjectConfirmation represents a SAML SubjectConfirmation
type SubjectConfirmation struct {
	Method string `xml:",attr"`

	NameID                  *NameID
	SubjectConfirmationData *SubjectConfirmationData
}

// Element returns SubjectConfirmation as etree.Element
func (r *SubjectConfirmation) Element() *etree.Element {
	e := etree.NewElement("saml:SubjectConfirmation")
	e.CreateAttr("Method", r.Method)
	if r.NameID != nil {
		e.AddChild(r.NameID.Element())
	}
	if r.SubjectConfirmationData != nil {
		e.AddChild(r.SubjectConfirmationData.Element())
	}
	return e
}

// SubjectConfirmationData represents a SAML SubjectConfirmationData
type SubjectConfirmationData struct {
	InResponseTo string `xml:",attr"`
	NotBefore    string `xml:",attr"`
	NotOnOrAfter string `xml:",attr"`
	Recipient    string `xml:",attr"`
}

// Element returns SubjectConfirmationData as etree.Element
func (r *SubjectConfirmationData) Element() *etree.Element {
	e := etree.NewElement("saml:SubjectConfirmationData")
	if r.InResponseTo != "" {
		e.CreateAttr("InResponseTo", r.InResponseTo)
	}
	if r.NotBefore != "" {
		e.CreateAttr("NotBefore", r.NotBefore)
	}
	if r.NotOnOrAfter != "" {
		e.CreateAttr("NotOnOrAfter", r.NotOnOrAfter)
	}
	if r.Recipient != "" {
		e.CreateAttr("Recipient", r.Recipient)
	}
	return e
}

// NameID represents a SAML NameID
type NameID struct {
	NameQualifier string `xml:",attr"`
	Format        string `xml:",attr"`
	Value         string `xml:",chardata"`
}

// Element returns NameID as etree.Element
func (r *NameID) Element() *etree.Element {
	e := etree.NewElement("saml:NameID")
	if r.NameQualifier != "" {
		e.CreateAttr("NameQualifier", r.NameQualifier)
	}
	if r.Format != "" {
		e.CreateAttr("Format", r.Format)
	}
	if r.Value != "" {
		e.SetText(r.Value)
	}
	return e
}

// AttributeStatement represents a SAML AttributeStatement
type AttributeStatement struct {
	Attributes []Attribute `xml:"Attribute"`
}

// Element returns AttributeStatement as etree.Element
func (r *AttributeStatement) Element() *etree.Element {
	e := etree.NewElement("saml:AttributeStatement")
	for _, v := range r.Attributes {
		e.AddChild(v.Element())
	}
	return e
}

// Attribute represents a SAML Attribute
type Attribute struct {
	FriendlyName    string           `xml:",attr"`
	Name            string           `xml:",attr"`
	NameFormat      string           `xml:",attr"`
	AttributeValues []AttributeValue `xml:"AttributeValue"`
}

// Element returns Attribute as etree.Element
func (r *Attribute) Element() *etree.Element {
	e := etree.NewElement("saml:Attribute")
	if r.FriendlyName != "" {
		e.CreateAttr("FriendlyName", r.FriendlyName)
	}
	if r.Name != "" {
		e.CreateAttr("Name", r.Name)
	}
	if r.NameFormat != "" {
		e.CreateAttr("NameFormat", r.NameFormat)
	}
	for _, v := range r.AttributeValues {
		e.AddChild(v.Element())
	}
	return e
}

// AttributeValue represents a SAML AttributeValue
type AttributeValue struct {
	Type   string `xml:"http://www.w3.org/2001/XMLSchema-instance type,attr"`
	Value  string `xml:",chardata"`
	NameID *NameID
}

// Element returns AttributeValue as etree.Element
func (r *AttributeValue) Element() *etree.Element {
	e := etree.NewElement("saml:AttributeValue")
	if r.Type != "" {
		e.CreateAttr("Type", r.Type)
	}
	if r.NameID != nil {
		e.AddChild(r.NameID.Element())
	}
	e.SetText(r.Value)
	return e
}
