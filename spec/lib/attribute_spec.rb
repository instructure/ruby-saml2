require_relative '../spec_helper'

module SAML2
  describe Attribute do
    let(:eduPersonPrincipalNameXML) { <<XML.strip
<saml:Attribute Name="urn:oid:1.3.6.1.4.1.5923.1.1.1.6" FriendlyName="eduPersonPrincipalName" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri" xmlns:x500="urn:oasis:names:tc:SAML:2.0:profiles:attribute:X500" x500:Encoding="LDAP" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">
  <saml:AttributeValue xsi:type="xsd:string">user@domain</saml:AttributeValue>
</saml:Attribute>
XML
  }

    it "should auto-parse X500 attributes" do
      attr = Attribute.from_xml(Nokogiri::XML(eduPersonPrincipalNameXML).root)
      attr.must_be_instance_of Attribute::X500
      attr.value.must_equal "user@domain"
      attr.name.must_equal Attribute::X500::EduPerson::PRINCIPAL_NAME
      attr.friendly_name.must_equal 'eduPersonPrincipalName'
      attr.name_format.must_equal Attribute::NameFormats::URI
    end

    it "should serialize an X500 attribute correctly" do
      attr = Attribute.create('eduPersonPrincipalName', 'user@domain')
      attr.must_be_instance_of Attribute::X500
      attr.value.must_equal "user@domain"
      attr.name.must_equal Attribute::X500::EduPerson::PRINCIPAL_NAME
      attr.friendly_name.must_equal 'eduPersonPrincipalName'
      attr.name_format.must_equal Attribute::NameFormats::URI

      doc = Nokogiri::XML::Builder.new do |builder|
        builder['saml'].Root('xmlns:saml' => Namespaces::SAML) do |builder|
          attr.build(builder)
          builder.parent.child['xmlns:saml'] = Namespaces::SAML
        end
      end.doc
      xml = doc.root.child.to_s
      xml.must_equal eduPersonPrincipalNameXML
    end
  end
end
