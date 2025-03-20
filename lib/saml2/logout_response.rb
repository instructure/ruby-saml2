# frozen_string_literal: true

require "saml2/status_response"

module SAML2
  class LogoutResponse < StatusResponse
    # @param logout_request [LogoutRequest]
    # @param sso [SSO, nil]
    # @param issuer [NameID]
    # @param status_code [String]
    # @param binding [String] the binding to use for the response
    # @return [LogoutResponse]
    def self.respond_to(logout_request,
                        sso,
                        issuer,
                        status_code = Status::SUCCESS,
                        binding: Bindings::HTTPRedirect::URN,
                        message: nil)
      logout_response = new
      logout_response.issuer = issuer
      if sso
        logout_response.destination = sso.single_logout_services.choose_endpoint(binding)&.effective_response_location
      end
      logout_response.in_response_to = logout_request.id
      logout_response.status.code = status_code
      logout_response.status.message = message
      logout_response
    end

    private

    def build(builder)
      builder["samlp"].LogoutResponse(
        "xmlns:samlp" => Namespaces::SAMLP,
        "xmlns:saml" => Namespaces::SAML
      ) do |logout_response|
        super(logout_response)
      end
    end
  end
end
