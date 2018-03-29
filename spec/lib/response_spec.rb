require_relative '../spec_helper'

module SAML2
  describe Response do
    let(:sp) { Entity.parse(fixture('service_provider.xml')).roles.first }

    let(:request) do
      request = AuthnRequest.parse(fixture('authnrequest.xml'))
      request.resolve(sp)
      request
    end

    let(:response) do
      Response.respond_to(request,
                          NameID.new('issuer'),
                          NameID.new('jacob', NameID::Format::PERSISTENT))
    end

    it "should generate valid XML" do
      xml = response.to_s
      expect(Schemas.protocol.validate(Nokogiri::XML(xml))).to eq []
    end

    def freeze_response
      response.instance_variable_set(:@id, "_9a15e699-2d04-4ba7-a521-cfa4dcd21f44")
      assertion = response.assertions.first
      assertion.instance_variable_set(:@id, "_cdfc3faf-90ad-462f-880d-677483210684")
      response.instance_variable_set(:@issue_instant, Time.parse("2015-02-12T22:51:29Z"))
      assertion.instance_variable_set(:@issue_instant, Time.parse("2015-02-12T22:51:29Z"))
      assertion.conditions.not_before = Time.parse("2015-02-12T22:51:24Z")
      assertion.conditions.not_on_or_after = Time.parse("2015-02-12T22:51:59Z")
      assertion.statements.first.authn_instant = Time.parse("2015-02-12T22:51:29Z")
      confirmation = assertion.subject.confirmation
      confirmation.not_on_or_after = Time.parse("2015-02-12T22:54:29Z")
      confirmation.recipient = response.destination
      confirmation.in_response_to = response.in_response_to
    end

    it "should generate a valid signature" do
      freeze_response
      response.sign(fixture('certificate.pem'), fixture('privatekey.key'))
      expect(Schemas.protocol.validate(response.to_xml)).to eq []
      # verifiable on the command line with:
      # xmlsec1 --verify --pubkey-cert-pem certificate.pem --privkey-pem privatekey.key --id-attr:ID urn:oasis:names:tc:SAML:2.0:assertion:Assertion response_signed.xml
      expect(response.to_s).to eq fixture('response_signed.xml')
    end

    it "should generate a valid signature when attributes are present" do
      freeze_response
      response.assertions.first.statements << sp.attribute_consuming_services.default.create_statement('givenName' => 'cody')
      response.sign(fixture('certificate.pem'), fixture('privatekey.key'))
      expect(response.to_s).to eq fixture('response_with_attribute_signed.xml')
    end

    it "should generate valid XML for IdP initiated response" do
      response = Response.initiate(sp, NameID.new('issuer'),
                              NameID.new('jacob', NameID::Format::PERSISTENT))
      expect(Schemas.protocol.validate(Nokogiri::XML(response.to_s))).to eq []
    end

    it "parses a serialized assertion" do
      response2 = Message.parse(response.to_s)
      expect(response2.assertions.length).to eq 1
      expect(response2.assertions.first.subject.name_id.id).to eq 'jacob'
    end

    it "doesn't validate a response with XSLT transforms" do
      response = Response.parse(fixture("xslt-transform-response.xml"))
      expect(response).to be_valid_schema
      expect(response.assertions.first.valid_signature?(fingerprint: 'bc71f7bacb36011694405dd0e2beafcc069de45f')).to eq false
    end

    it "doesn't validate a response with external URI reference in the signature" do
      response = Response.parse(fixture("external-uri-reference-response.xml"))
      expect(response).to be_valid_schema
      expect(response.assertions.first.valid_signature?(fingerprint: 'bc71f7bacb36011694405dd0e2beafcc069de45f')).to eq false
    end

    it "can decrypt an EncryptedAssertion" do
      # verifiable on the command line with:
      # xmlsec1 decrypt --privkey-pem privatekey.key response_with_encrypted_assertion.xml
      response = Response.parse(fixture("response_with_encrypted_assertion.xml"))
      expect(response.decrypt(fixture("privatekey.key"))).to eq true
      expect(response.assertions.length).to eq 1
      expect(response.assertions.first.subject.name_id.id).to eq 'jacob'
    end
  end
end
