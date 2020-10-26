# frozen_string_literal: true

require_relative '../spec_helper'

module SAML2
  describe Attribute do
    def serialize(attribute)
      doc = Nokogiri::XML::Builder.new do |builder|
        builder['saml'].Root('xmlns:saml' => Namespaces::SAML) do |root|
          attribute.build(root)
          root.parent.child['xmlns:saml'] = Namespaces::SAML
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
      expect(attr).to be_instance_of Attribute::X500
      expect(attr.value).to eq "user@domain"
      expect(attr.name).to eq Attribute::X500::EduPerson::PRINCIPAL_NAME
      expect(attr.friendly_name).to eq 'eduPersonPrincipalName'
      expect(attr.name_format).to eq Attribute::NameFormats::URI
    end

    it "recognizes and X500 attribute without a NameFormat" do
      xml = <<-XML
        <saml:Attribute xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" Name="urn:oid:1.3.6.1.4.1.5923.1.1.1.6"><saml:AttributeValue xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="xs:string">user@domain</saml:AttributeValue></saml:Attribute>
      XML
      attr = Attribute.from_xml(Nokogiri::XML(xml).root)
      expect(attr).to be_instance_of Attribute::X500
      expect(attr.value).to eq "user@domain"
      expect(attr.name).to eq Attribute::X500::EduPerson::PRINCIPAL_NAME
      expect(attr.friendly_name).to eq 'eduPersonPrincipalName'
      expect(attr.name_format).to eq nil
    end

    it "should serialize an X500 attribute correctly" do
      attr = Attribute.create('eduPersonPrincipalName', 'user@domain')
      expect(attr).to be_instance_of Attribute::X500
      expect(attr.value).to eq "user@domain"
      expect(attr.name).to eq Attribute::X500::EduPerson::PRINCIPAL_NAME
      expect(attr.friendly_name).to eq 'eduPersonPrincipalName'
      expect(attr.name_format).to eq Attribute::NameFormats::URI

      expect(serialize(attr)).to eq eduPersonPrincipalNameXML
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
      expect(stmt.attributes.first.value).to eq true

      # serializes canonically
      expect(serialize(stmt)).to eq(xml.sub('>1<', '>true<'))
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
      expect(stmt.attributes.first.value).to eq Time.at(1435603023)

      # serializes canonically
      expect(serialize(stmt)).to eq xml
    end

    it "should parse values with different namespace prefixes" do
      xml = <<XML.strip
<saml:Attribute Name="attr" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:xssi="http://www.w3.org/2001/XMLSchema-instance">
  <saml:AttributeValue xssi:type="xsd:boolean">0</saml:AttributeValue>
</saml:Attribute>
XML

      attr = Attribute.from_xml(Nokogiri::XML(xml).root)
      expect(attr.value).to eq false
    end

    it "should parse untagged values" do
      xml = <<XML.strip
<saml:Attribute Name="attr" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">
  <saml:AttributeValue>something</saml:AttributeValue>
</saml:Attribute>
XML

      attr = Attribute.from_xml(Nokogiri::XML(xml).root)
      expect(attr.value).to eq "something"
    end

  end

  describe AttributeStatement do
    describe "#to_h" do
      it "works" do
        attr_statement = Response.parse(fixture("response_with_attribute_signed.xml")).assertions.first.attribute_statements.first
        expect(attr_statement.to_h(:friendly_name)).to eq('givenName' => 'cody')
        expect(attr_statement.to_h(:name)).to eq("urn:oid:2.5.4.42" => 'cody')
        expect(attr_statement.to_h(:both)).to eq('givenName' => 'cody', "urn:oid:2.5.4.42" => 'cody')
      end

      it "infers friendly names if possible" do
        attr_statement = Response.parse(fixture("test3-response.xml")).assertions.first.attribute_statements.first
        expect(attr_statement.to_h).to eq({
            'urn:oid:1.3.6.1.4.1.5923.1.1.1.1' => 'member',
            'urn:oid:1.3.6.1.4.1.5923.1.1.1.6' => 'student@example.edu',
            'eduPersonAffiliation' => 'member',
            'eduPersonPrincipalName' => 'student@example.edu'})
      end

      it "properly combines repeated attributes" do
        attr_statement = AttributeStatement.from_xml(Nokogiri::XML(<<-XML).root)
<saml2:AttributeStatement xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion">
  <saml2:Attribute FriendlyName="eduPersonScopedAffiliation" Name="urn:oid:1.3.6.1.4.1.5923.1.1.1.9" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri">
    <saml2:AttributeValue>02</saml2:AttributeValue>
  </saml2:Attribute>
  <saml2:Attribute FriendlyName="eduPersonScopedAffiliation" Name="urn:oid:1.3.6.1.4.1.5923.1.1.1.9" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri">
    <saml2:AttributeValue>employee@school.edu</saml2:AttributeValue>
    <saml2:AttributeValue>students@school.edu</saml2:AttributeValue>
  </saml2:Attribute>
</saml2:AttributeStatement>
        XML

        expect(attr_statement.to_h(:friendly_name)).to eq({
            'eduPersonScopedAffiliation' => ['02', 'employee@school.edu', 'students@school.edu']
                                          })
      end
    end
  end
end
