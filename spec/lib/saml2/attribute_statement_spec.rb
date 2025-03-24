# frozen_string_literal: true

module SAML2
  describe AttributeStatement do
    describe "#to_h" do
      it "works" do
        attr_statement = Response.parse(fixture("response_with_attribute_signed.xml"))
                                 .assertions.first.attribute_statements.first
        expect(attr_statement.to_h(:friendly_name)).to eq("givenName" => "cody")
        expect(attr_statement.to_h(:name)).to eq("urn:oid:2.5.4.42" => "cody")
        expect(attr_statement.to_h(:both)).to eq("givenName" => "cody", "urn:oid:2.5.4.42" => "cody")
      end

      it "infers friendly names if possible" do
        attr_statement = Response.parse(fixture("test3-response.xml")).assertions.first.attribute_statements.first
        expect(attr_statement.to_h).to eq({
                                            "urn:oid:1.3.6.1.4.1.5923.1.1.1.1" => "member",
                                            "urn:oid:1.3.6.1.4.1.5923.1.1.1.6" => "student@example.edu",
                                            "eduPersonAffiliation" => "member",
                                            "eduPersonPrincipalName" => "student@example.edu"
                                          })
      end

      it "properly combines repeated attributes" do
        attr_statement = AttributeStatement.from_xml(Nokogiri::XML(<<~XML).root)
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
                                                            "eduPersonScopedAffiliation" => ["02",
                                                                                             "employee@school.edu",
                                                                                             "students@school.edu"]
                                                          })
      end
    end
  end
end
