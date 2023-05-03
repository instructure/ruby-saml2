# frozen_string_literal: true

require_relative "../spec_helper"

module SAML2
  describe Signable do
    describe "#valid_signature?" do
      it "can work with an explicit key from metadata" do
        response = Response.parse(fixture("response_with_rsa_key_value.xml"))
        key = response.assertions.first.signing_key.key
        expect(response.assertions.first.valid_signature?(key: [key])).to be true
      end
    end
  end
end
