# frozen_string_literal: true

module SAML2
  describe LogoutResponse do
    let(:idp) { Entity.parse(fixture("identity_provider.xml")).roles.first }

    let(:logout_request) do
      LogoutRequest.initiate(idp,
                             NameID.new("issuer"),
                             NameID.new("jacob",
                                        name_qualifier: "a",
                                        sp_name_qualifier: "b"),
                             "abc")
    end
    let(:logout_response) do
      LogoutResponse.respond_to(logout_request, idp, NameID.new("issuer2"))
    end

    let(:multicode_xml) do
      <<~XML
        <?xml version="1.0"?>
        <samlp:LogoutResponse xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_f93ca540-f984-4eaa-b311-2b18a0359f25" Version="2.0" IssueInstant="2025-10-15T22:44:56Z">
          <samlp:Status>
            <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Requester">
              <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:InvalidNameIDPolicy"/>
            </samlp:StatusCode>
          </samlp:Status>
        </samlp:LogoutResponse>
      XML
    end

    it "should generate valid XML" do
      xml = logout_response.to_s
      expect(Schemas.protocol.validate(Nokogiri::XML(xml))).to eq []
    end

    it "parses" do
      # yup, I'm lazy
      new_response = LogoutResponse.parse(logout_response.to_s)
      expect(new_response.issuer.id).to eq "issuer2"
      expect(new_response.status.code).to eq Status::SUCCESS
    end

    it "parses nested codes" do
      new_response = LogoutResponse.parse(multicode_xml)
      expect(new_response.status.codes).to eql [Status::REQUESTER, Status::INVALID_NAME_ID_POLICY]
    end

    def strip_id_and_issue_instant(xml)
      xml.sub(/ ID="_[a-z0-9\-]+"/, "")
         .sub(/ IssueInstant="[0-9TZ:\-]+"/, "")
    end

    it "serializes nested codes" do
      logout_response = LogoutResponse.new
      logout_response.status.codes = [Status::REQUESTER, Status::INVALID_NAME_ID_POLICY]
      expect(strip_id_and_issue_instant(logout_response.to_s)).to eql strip_id_and_issue_instant(multicode_xml)
    end
  end
end
