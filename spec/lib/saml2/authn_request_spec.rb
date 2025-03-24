# frozen_string_literal: true

module SAML2
  describe AuthnRequest do
    let(:sp) { Entity.parse(fixture("service_provider.xml")).roles.first }
    let(:request) { AuthnRequest.parse(fixture("authnrequest.xml")) }

    it "should be valid" do
      expect(request.valid_schema?).to be true
      expect(request.resolve(sp)).to be true
      expect(request.assertion_consumer_service.location).to eq "https://siteadmin.test.instructure.com/saml_consume"
    end

    it "should not be valid if the ACS url is not in the SP" do
      allow(request).to receive(:assertion_consumer_service_url).and_return("garbage")
      expect(request.resolve(sp)).to be false
    end

    it "should use the default ACS if not specified" do
      allow(request).to receive(:assertion_consumer_service_url).and_return(nil)
      expect(request.resolve(sp)).to be true
      expect(request.assertion_consumer_service.location).to eq "https://siteadmin.instructure.com/saml_consume"
    end

    it "should find the ACS by index" do
      allow(request).to receive_messages(assertion_consumer_service_url: nil, assertion_consumer_service_index: 2)
      expect(request.resolve(sp)).to be true
      expect(request.assertion_consumer_service.location).to eq "https://siteadmin.beta.instructure.com/saml_consume"
    end

    it "should find the NameID policy" do
      expect(request.name_id_policy).to eq NameID::Policy.new(true,
                                                              NameID::Format::PERSISTENT,
                                                              "moodle.bridge.feide.no")
    end

    it "parses RequestedAuthnContext" do
      expect(request.requested_authn_context).not_to be_nil
      expect(request.requested_authn_context.class_ref).to eql(
        ["urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport"]
      )
    end

    it "serializes valid XML" do
      authn_request = AuthnRequest.initiate(NameID.new("entity"),
                                            assertion_consumer_service: Endpoint.new("https://somewhere/"))
      authn_request.requested_authn_context =
        RequestedAuthnContext.new("urn:oasis:names:tc:SAML:2.0:ac:classes:Password")
      authn_request.requested_authn_context.comparison = :exact
      authn_request.passive = true
      xml = authn_request.to_s
      authn_request = AuthnRequest.parse(xml)
      expect(authn_request).to be_valid_schema
      expect(authn_request.force_authn?).to be_nil
      expect(authn_request.passive?).to be true
    end
  end
end
