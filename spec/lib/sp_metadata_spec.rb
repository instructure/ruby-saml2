require_relative '../spec_helper'

module SAML2
  describe SPMetadata do
    it "should parse and validate" do
      sp = SPMetadata.parse(fixture('spmetadata.xml'))
      sp.valid_schema?.must_equal true
    end

    it "should parse valid XML, but validate failure" do
      sp = SPMetadata.parse("<xml></xml>")
      sp.valid_schema?.must_equal false
    end

    it "should not validate non-XML" do
      sp = SPMetadata.parse("garbage")
      sp.valid_schema?.must_equal false
    end

    describe "valid metadata" do
      let(:sp) { SPMetadata.parse(fixture('spmetadata.xml')) }

      it "should find the issuer" do
        sp.entity_id.must_equal "http://siteadmin.instructure.com/saml2"
      end

      it "should create the assertion_consumer_services array" do
        sp.assertion_consumer_services.length.must_equal 4
        sp.assertion_consumer_services.map(&:index).must_equal [0, 1, 2, 3]
        sp.assertion_consumer_services.first.location.must_equal 'https://siteadmin.instructure.com/saml_consume'
      end

      it "should find the signing certificate" do
        sp.signing_certificate.must_match /MIIE8TCCA9mgAwIBAgIJAITusxON60cKMA0GCSqGSIb3DQEBBQUAMIGrMQswCQYD/
      end

      it "should parse the organization" do
        sp.organization.display_name.must_equal 'Canvas'
        sp.organization.display_name('en').must_equal 'Canvas'
        sp.organization.display_name('es').must_equal nil
        sp.organization.display_name(:all).must_equal en: 'Canvas'
      end
    end
  end
end
