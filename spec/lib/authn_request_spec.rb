require_relative '../spec_helper'

module SAML2
  describe AuthnRequest do
    let(:sp) { SPMetadata.parse(fixture('spmetadata.xml')) }
    let(:request) { AuthnRequest.parse(fixture('authnrequest.xml')) }

    it "should be valid" do
      request.valid_schema?.must_equal true
      request.resolve(sp).must_equal true
      request.assertion_consumer_service.location.must_equal "https://siteadmin.test.instructure.com/saml_consume"
    end

    it "should not be valid if the ACS url is not in the SP" do
      request.stub(:assertion_consumer_service_url, "garbage") do
        request.resolve(sp).must_equal false
      end
    end

    it "should use the default ACS if not specified" do
      request.stub(:assertion_consumer_service_url, nil) do
        request.resolve(sp).must_equal true
        request.assertion_consumer_service.location.must_equal "https://siteadmin.instructure.com/saml_consume"
      end
    end

    it "should find the ACS by index" do
      request.stub(:assertion_consumer_service_url, nil) do
        request.stub(:assertion_consumer_service_index, 2) do
          request.resolve(sp).must_equal true
          request.assertion_consumer_service.location.must_equal "https://siteadmin.beta.instructure.com/saml_consume"
        end
      end
    end

    it "should find the NameID policy" do
      request.name_id_policy.must_equal NameID::Policy.new(true, NameID::Format::PERSISTENT)
    end
  end
end
