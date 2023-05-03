# frozen_string_literal: true

require "saml2/name_id"
require "saml2/request"

module SAML2
  class LogoutRequest < Request
    attr_writer :name_id, :session_index

    # @param sso [SSO]
    # @param issuer [NameID]
    # @param name_id [NameID]
    # @param session_index optional [String, Array<String>]
    # @return [LogoutRequest]
    def self.initiate(sso, issuer, name_id, session_index = [])
      logout_request = new
      logout_request.issuer = issuer
      logout_request.destination = sso.single_logout_services.first.location
      logout_request.name_id = name_id
      logout_request.session_index = session_index

      logout_request
    end

    # @return [NameID]
    def name_id
      @name_id ||= (NameID.from_xml(xml.at_xpath("saml:NameID", Namespaces::ALL)) if xml)
    end

    # @return [String, Array<String>]
    def session_index
      @session_index ||= (load_string_array(xml, "samlp:SessionIndex") if xml)
    end

    private

    def build(builder)
      builder["samlp"].LogoutRequest(
        "xmlns:samlp" => Namespaces::SAMLP,
        "xmlns:saml" => Namespaces::SAML
      ) do |logout_request|
        super(logout_request)

        name_id.build(logout_request)

        Array(session_index).each do |session_index_instance|
          logout_request["samlp"].SessionIndex(session_index_instance)
        end
      end
    end
  end
end
