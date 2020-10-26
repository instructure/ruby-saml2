# frozen_string_literal: true

require_relative '../spec_helper'

module SAML2
  describe IdentityProvider do
    it "should serialize valid xml" do
      entity = Entity.new
      entity.entity_id = 'http://sso.canvaslms.com/SAML2'
      entity.organization = Organization.new('Canvas', 'Canvas by Instructure', 'https://www.canvaslms.com/')
      contact = Contact.new(Contact::Type::TECHNICAL)
      contact.company = 'Instructure'
      contact.email_addresses << 'mailto:ops@instructure.com'
      entity.contacts << contact

      idp = IdentityProvider.new
      idp.name_id_formats << NameID::Format::PERSISTENT
      idp.single_sign_on_services << Endpoint.new('https://sso.canvaslms.com/SAML2/Login')
      idp.keys << KeyDescriptor.new('somedata', KeyDescriptor::Type::SIGNING)

      entity.roles << idp
      expect(Schemas.metadata.validate(Nokogiri::XML(entity.to_s))).to eq []
    end

    describe "valid metadata" do
      let(:entity) { Entity.parse(fixture('identity_provider.xml')) }
      let(:idp) { entity.roles.first }

      it "should create the single_sign_on_services array" do
        expect(idp.single_sign_on_services.length).to eq 3
        expect(idp.single_sign_on_services.first.location).to eq 'https://sso.school.edu/idp/profile/Shibboleth/SSO'
      end

      it "should find the signing certificate" do
        expect(idp.keys.first.x509).to match(/MIIE8TCCA9mgAwIBAgIJAITusxON60cKMA0GCSqGSIb3DQEBBQUAMIGrMQswCQYD/)
      end

      it "loads identity provider attributes" do
        expect(idp.want_authn_requests_signed?).to be_truthy
      end
    end
  end
end
