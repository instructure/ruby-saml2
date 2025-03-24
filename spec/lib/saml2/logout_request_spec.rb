# frozen_string_literal: true

module SAML2
  describe LogoutRequest do
    let(:idp) { Entity.parse(fixture("identity_provider.xml")).roles.first }

    let(:logout_request) do
      LogoutRequest.initiate(idp,
                             NameID.new("issuer"),
                             NameID.new("jacob",
                                        name_qualifier: "a",
                                        sp_name_qualifier: "b"),
                             "abc")
    end

    it "should generate valid XML" do
      xml = logout_request.to_s
      expect(Schemas.protocol.validate(Nokogiri::XML(xml))).to eq []
    end

    it "parses" do
      # yup, I'm lazy
      new_request = LogoutRequest.parse(logout_request.to_s)
      expect(new_request.issuer.id).to eq "issuer"
      expect(new_request.name_id.id).to eq "jacob"
      expect(new_request.name_id.name_qualifier).to eq "a"
      expect(new_request.name_id.sp_name_qualifier).to eq "b"
      expect(new_request.session_index).to eq ["abc"]
    end
  end
end
