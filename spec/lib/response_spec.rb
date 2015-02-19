require_relative '../spec_helper'

module SAML2
  describe Response do
    let(:sp) { SPMetadata.parse(fixture('spmetadata.xml')) }

    let(:request) do
      request = AuthnRequest.parse(fixture('authnrequest.xml'))
      request.resolve(sp)
      request
    end

    let(:response) do
      response = Response.respond_to(request,
                                     NameID.new('issuer'),
                                     NameID.new('jacob', NameID::Format::PERSISTENT))
      response
    end

    it "should generate valid XML" do
      xml = response.to_s
      Schemas.protocol.validate(Nokogiri::XML(xml)).must_equal []
    end

    it "should generate a valid signature" do
      response.instance_variable_set(:@id, "_9a15e699-2d04-4ba7-a521-cfa4dcd21f44")
      response.assertions.first.instance_variable_set(:@id, "_cdfc3faf-90ad-462f-880d-677483210684")
      response.instance_variable_set(:@issue_instant, Time.parse("2015-02-12T22:51:29Z"))
      response.assertions.first.instance_variable_set(:@issue_instant, Time.parse("2015-02-12T22:51:29Z"))
      response.sign(fixture('certificate.pem'), fixture('privatekey.key'))
      # verifiable on the command line with:
      # xmlsec1 --verify --pubkey-cert-pem certificate.pem --privkey-pem privatekey.key --id-attr:ID urn:oasis:names:tc:SAML:2.0:assertion:Assertion response_signed.xml
      response.to_s.must_equal fixture('response_signed.xml')
    end
  end
end
