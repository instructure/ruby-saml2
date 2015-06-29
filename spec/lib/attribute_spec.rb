require_relative '../spec_helper'

module SAML2
  describe Attribute do
    def serialize(attribute)
      doc = Nokogiri::XML::Builder.new do |builder|
        builder['saml'].Root('xmlns:saml' => Namespaces::SAML) do |builder|
          attribute.build(builder)
          builder.parent.child['xmlns:saml'] = Namespaces::SAML
        end
      end.doc
      doc.root.child.to_s
    end

    let(:eduPersonPrincipalNameXML) { <<XML.strip
<saml:Attribute xmlns:x500="urn:oasis:names:tc:SAML:2.0:profiles:attribute:X500" Name="urn:oid:1.3.6.1.4.1.5923.1.1.1.6" FriendlyName="eduPersonPrincipalName" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri" x500:Encoding="LDAP" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">
  <saml:AttributeValue xsi:type="xs:string">user@domain</saml:AttributeValue>
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

      serialize(attr).must_equal eduPersonPrincipalNameXML
    end

    it "should parse and serialize boolean values" do
      xml = <<XML.strip
<saml:AttributeStatement xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">
  <saml:Attribute Name="attr">
    <saml:AttributeValue xsi:type="xs:boolean">1</saml:AttributeValue>
  </saml:Attribute>
</saml:AttributeStatement>
XML

      stmt = AttributeStatement.from_xml(Nokogiri::XML(xml).root)
      stmt.attributes.first.value.must_equal true

      # serializes canonically
      serialize(stmt).must_equal(xml.sub('>1<', '>true<'))
    end

    it "should parse and serialize dateTime values" do
      xml = <<XML.strip
<saml:AttributeStatement xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">
  <saml:Attribute Name="attr">
    <saml:AttributeValue xsi:type="xs:dateTime">2015-06-29T18:37:03Z</saml:AttributeValue>
  </saml:Attribute>
</saml:AttributeStatement>
XML

      stmt = AttributeStatement.from_xml(Nokogiri::XML(xml).root)
      stmt.attributes.first.value.must_equal Time.at(1435603023)

      # serializes canonically
      serialize(stmt).must_equal(xml)
    end

    it "should parse values with different namespace prefixes" do
      xml = <<XML.strip
<saml:Attribute Name="attr" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:xssi="http://www.w3.org/2001/XMLSchema-instance">
  <saml:AttributeValue xssi:type="xsd:boolean">0</saml:AttributeValue>
</saml:Attribute>
XML

      attr = Attribute.from_xml(Nokogiri::XML(xml).root)
      attr.value.must_equal false
    end

    it "should parse untagged values" do
      xml = <<XML.strip
<saml:Attribute Name="attr" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">
  <saml:AttributeValue>something</saml:AttributeValue>
</saml:Attribute>
XML

      attr = Attribute.from_xml(Nokogiri::XML(xml).root)
      attr.value.must_equal "something"
    end

  end
end
