require_relative '../spec_helper'

module SAML2
  describe LogoutRequest do
    let(:idp) { Entity.parse(fixture('identity_provider.xml')).roles.first }

    let(:logout_request) {
      LogoutRequest.initiate(idp,
                             NameID.new('issuer'),
                             NameID.new('jacob',
                                        name_qualifier: "a",
                                        sp_name_qualifier: "b"),
                             "abc")
    }

    it "should generate valid XML" do
      xml = logout_request.to_s
      expect(Schemas.protocol.validate(Nokogiri::XML(xml))).to eq []
    end
  end
end
