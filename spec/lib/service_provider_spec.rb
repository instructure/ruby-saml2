require_relative '../spec_helper'

module SAML2
  describe ServiceProvider do
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
