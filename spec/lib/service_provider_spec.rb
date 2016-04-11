require_relative '../spec_helper'

module SAML2
  describe ServiceProvider do
    describe "valid metadata" do
      let(:entity) { Entity.parse(fixture('service_provider.xml')) }
      let(:sp) { entity.roles.first }

      it "should create the assertion_consumer_services array" do
        sp.assertion_consumer_services.length.must_equal 4
        sp.assertion_consumer_services.map(&:index).must_equal [0, 1, 2, 3]
        sp.assertion_consumer_services.first.location.must_equal 'https://siteadmin.instructure.com/saml_consume'
      end

      it "should find the signing certificate" do
        sp.signing_keys.first.x509.must_match(/MIIE8TCCA9mgAwIBAgIJAITusxON60cKMA0GCSqGSIb3DQEBBQUAMIGrMQswCQYD/)
      end

      it "should load the organization" do
        entity.organization.display_name.must_equal 'Canvas'
      end

      it "should load contacts" do
        entity.contacts.length.must_equal 1
        entity.contacts.first.type.must_equal Contact::Type::TECHNICAL
        entity.contacts.first.surname.must_equal 'Administrator'
      end
    end
  end
end
