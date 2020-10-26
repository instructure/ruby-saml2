# frozen_string_literal: true

require_relative '../spec_helper'

module SAML2
  describe ServiceProvider do
    it "should serialize valid xml" do
      entity = Entity.new
      entity.entity_id = 'http://sso.canvaslms.com/SAML2'
      entity.organization = Organization.new('Canvas', 'Canvas by Instructure', 'https://www.canvaslms.com/')
      contact = Contact.new(Contact::Type::TECHNICAL)
      contact.company = 'Instructure'
      contact.email_addresses << 'mailto:ops@instructure.com'
      entity.contacts << contact

      sp = ServiceProvider.new
      sp.single_logout_services << Endpoint.new('https://sso.canvaslms.com/SAML2/Logout',
                                                 Bindings::HTTPRedirect::URN)
      sp.assertion_consumer_services << Endpoint::Indexed.new('https://sso.canvaslms.com/SAML2/Login1')
      sp.assertion_consumer_services << Endpoint::Indexed.new('https://sso.canvaslms.com/SAML2/Login2')
      sp.keys << KeyDescriptor.new('somedata', KeyDescriptor::Type::ENCRYPTION, [KeyDescriptor::EncryptionMethod.new])
      sp.keys << KeyDescriptor.new('somedata', KeyDescriptor::Type::SIGNING)
      acs = AttributeConsumingService.new
      acs.name[:en] = 'service'
      acs.requested_attributes << RequestedAttribute.create('uid')
      sp.attribute_consuming_services << acs

      entity.roles << sp
      expect(Schemas.metadata.validate(Nokogiri::XML(entity.to_s))).to eq []
    end

    describe "valid metadata" do
      let(:entity) { Entity.parse(fixture('service_provider.xml')) }
      let(:sp) { entity.roles.first }

      it "should create the assertion_consumer_services array" do
        expect(sp.assertion_consumer_services.length).to eq 4
        expect(sp.assertion_consumer_services.map(&:index)).to eq [0, 1, 2, 3]
        expect(sp.assertion_consumer_services.first.location).to eq 'https://siteadmin.instructure.com/saml_consume'
      end

      it "should find the signing certificate" do
        expect(sp.signing_keys.first.x509).to match(/MIIE8TCCA9mgAwIBAgIJAITusxON60cKMA0GCSqGSIb3DQEBBQUAMIGrMQswCQYD/)
      end

      it "should load the organization" do
        expect(entity.organization.display_name.to_s).to eq 'Canvas'
      end

      it "should load contacts" do
        expect(entity.contacts.length).to eq 1
        expect(entity.contacts.first.type).to eq Contact::Type::TECHNICAL
        expect(entity.contacts.first.surname).to eq 'Administrator'
      end

      it "loads attribute_consuming_services" do
        expect(sp.attribute_consuming_services.length).to eq 1
        acs = sp.attribute_consuming_services.first
        expect(acs.index).to eq 0
        expect(acs.name.to_s).to eq 'service'
        expect(acs.requested_attributes.length).to eq 1
        expect(acs.requested_attributes.first.name).to eq 'urn:oid:2.5.4.42'
      end

      it "loads the key info" do
        expect(sp.keys.first.encryption_methods.first.algorithm).to eq KeyDescriptor::EncryptionMethod::Algorithm::AES128_CBC
        expect(sp.keys.first.encryption_methods.first.key_size).to eq 128
      end

      it "loads service provider attributes" do
        expect(sp.authn_requests_signed?).to be_truthy
        expect(sp.want_assertions_signed?).to be_truthy
      end
    end
  end
end
