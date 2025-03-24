# frozen_string_literal: true

module SAML2
  describe Endpoint do
    describe "#effective_response_location" do
      it "returns the location if response_location is not present" do
        expect(Endpoint.new("http://example.com", Bindings::HTTPRedirect::URN).effective_response_location).to eql "http://example.com"
      end

      it "returns the response_location if it is present" do
        expect(Endpoint.new("http://example.com", Bindings::HTTPRedirect::URN, "http://example.com/response").effective_response_location)
          .to eql "http://example.com/response"
      end
    end
  end
end
