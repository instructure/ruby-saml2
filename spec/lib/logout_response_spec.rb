# frozen_string_literal: true

require_relative '../spec_helper'

module SAML2
  describe LogoutResponse do
    let(:idp) { Entity.parse(fixture('identity_provider.xml')).roles.first }

    let(:logout_request) {
      LogoutRequest.initiate(idp,
                             NameID.new('issuer'),
                             NameID.new('jacob',
                                        name_qualifier: "a",
                                        sp_name_qualifier: "b"),
                             "abc")
    }
    let(:logout_response) {
      LogoutResponse.respond_to(logout_request, idp, NameID.new('issuer2'))
    }

    it "should generate valid XML" do
      xml = logout_response.to_s
      expect(Schemas.protocol.validate(Nokogiri::XML(xml))).to eq []
    end

    it "parses" do
      # yup, I'm lazy
      new_response = LogoutResponse.parse(logout_response.to_s)
      expect(new_response.issuer.id).to eq 'issuer2'
      expect(new_response.status.code).to eq Status::SUCCESS
    end
  end
end
