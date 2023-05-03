# frozen_string_literal: true

require_relative "../spec_helper"

module SAML2
  describe KeyInfo do
    describe ".format_fingerprint" do
      it "strips non-hexadecimal characters" do
        expect(KeyInfo.format_fingerprint("\u200F abcdefghijklmnop 1234567890-\n a1"))
          .to eq("ab:cd:ef:12:34:56:78:90:a1")
      end
    end

    describe "#certificate" do
      it "doesn't asplode if the keyinfo is just an rsa key value" do
        response = Nokogiri::XML(fixture("response_with_rsa_key_value.xml"))
        key = KeyInfo.from_xml(response.at_xpath("//dsig:KeyInfo", Namespaces::ALL))
        expect(key.certificate).to be_nil
        expect(key.fingerprint).to be_nil
        expect(key.key).not_to be_nil
      end
    end
  end
end
