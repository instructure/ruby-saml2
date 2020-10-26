# frozen_string_literal: true

require_relative '../spec_helper'

module SAML2
  describe AuthnRequest do
    let(:sp) { Entity.parse(fixture('service_provider.xml')).roles.first }
    let(:request) { AuthnRequest.parse(fixture('authnrequest.xml')) }

    it "should be valid" do
      expect(request.valid_schema?).to eq true
      expect(request.resolve(sp)).to eq true
      expect(request.assertion_consumer_service.location).to eq "https://siteadmin.test.instructure.com/saml_consume"
    end

    it "should not be valid if the ACS url is not in the SP" do
      allow(request).to receive(:assertion_consumer_service_url).and_return("garbage")
      expect(request.resolve(sp)).to eq false
    end

    it "should use the default ACS if not specified" do
      allow(request).to receive(:assertion_consumer_service_url).and_return(nil)
      expect(request.resolve(sp)).to eq true
      expect(request.assertion_consumer_service.location).to eq "https://siteadmin.instructure.com/saml_consume"
    end

    it "should find the ACS by index" do
      allow(request).to receive(:assertion_consumer_service_url).and_return(nil)
      allow(request).to receive(:assertion_consumer_service_index).and_return(2)
      expect(request.resolve(sp)).to eq true
      expect(request.assertion_consumer_service.location).to eq "https://siteadmin.beta.instructure.com/saml_consume"
    end

    it "should find the NameID policy" do
      expect(request.name_id_policy).to eq NameID::Policy.new(true, NameID::Format::PERSISTENT, "moodle.bridge.feide.no")
    end

    it 'serializes valid XML' do
      authn_request = AuthnRequest.initiate(NameID.new("entity"),
        assertion_consumer_service: Endpoint.new('https://somewhere/'))
      authn_request.requested_authn_context = RequestedAuthnContext.new
      authn_request.requested_authn_context.class_ref = "urn:oasis:names:tc:SAML:2.0:ac:classes:Password"
      authn_request.requested_authn_context.comparison = :exact
      authn_request.passive = true
      xml = authn_request.to_s
      authn_request = AuthnRequest.parse(xml)
      expect(authn_request).to be_valid_schema
      expect(authn_request.force_authn?).to eq nil
      expect(authn_request.passive?).to eq true
    end
  end
end
