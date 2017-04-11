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
                                                 Endpoint::Bindings::HTTP_REDIRECT)
      sp.assertion_consumer_services << Endpoint::Indexed.new('https://sso.canvaslms.com/SAML2/Login1', 0)
      sp.assertion_consumer_services << Endpoint::Indexed.new('https://sso.canvaslms.com/SAML2/Login2', 1)
      sp.keys << Key.new('somedata', Key::Type::ENCRYPTION, [Key::EncryptionMethod.new])
      sp.keys << Key.new('somedata', Key::Type::SIGNING)

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
        expect(entity.organization.display_name).to eq 'Canvas'
      end

      it "should load contacts" do
        expect(entity.contacts.length).to eq 1
        expect(entity.contacts.first.type).to eq Contact::Type::TECHNICAL
        expect(entity.contacts.first.surname).to eq 'Administrator'
      end
    end
  end
end
