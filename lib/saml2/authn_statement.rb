# frozen_string_literal: true

require "saml2/base"

module SAML2
  class AuthnStatement < Base
    module Classes
      INTERNET_PROTOCOL =
        "urn:oasis:names:tc:SAML:2.0:ac:classes:InternetProtocol" # IP address
      INTERNET_PROTOCOL_PASSWORD =
        "urn:oasis:names:tc:SAML:2.0:ac:classes:InternetProtocolPassword" # IP address, as well as username/password
      KERBEROS =
        "urn:oasis:names:tc:SAML:2.0:ac:classes:Kerberos"
      PASSWORD =
        "urn:oasis:names:tc:SAML:2.0:ac:classes:Password" # username/password, NOT over SSL
      PASSWORD_PROTECTED_TRANSPORT =
        "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport" # username/password over SSL
      PREVIOUS_SESSION =
        "urn:oasis:names:tc:SAML:2.0:ac:classes:PreviousSession" # remember me
      SMARTCARD =
        "urn:oasis:names:tc:SAML:2.0:ac:classes:Smartcard"
      SMARTCARD_PKI =
        "urn:oasis:names:tc:SAML:2.0:ac:classes:SmartcardPKI" # smartcard with a private key on it
      TLS_CLIENT =
        "urn:oasis:names:tc:SAML:2.0:ac:classes:TLSClient" # SSL client certificate
      UNSPECIFIED =
        "urn:oasis:names:tc:SAML:2.0:ac:classes:unspecified"
    end

    # @return [Time]
    attr_accessor :authn_instant
    # One of the values in {Classes}.
    # @return [String, nil]
    attr_accessor :authn_context_class_ref
    # @return [String, nil]
    attr_accessor :session_index
    # @return [Time, nil]
    attr_accessor :session_not_on_or_after

    # (see Base#from_xml)
    def from_xml(node)
      super
      @authn_instant = Time.parse(node["AuthnInstant"])
      @session_index = node["SessionIndex"]
      @session_not_on_or_after = Time.parse(node["SessionNotOnOrAfter"]) if node["SessionNotOnOrAfter"]
      @authn_context_class_ref = node.at_xpath("saml:AuthnContext/saml:AuthnContextClassRef",
                                               Namespaces::ALL)&.content&.strip
    end

    # (see Base#build)
    def build(builder)
      builder["saml"].AuthnStatement("AuthnInstant" => authn_instant.iso8601) do |authn_statement|
        authn_statement.parent["SessionIndex"] = session_index if session_index
        authn_statement.parent["SessionNotOnOrAfter"] = session_not_on_or_after.iso8601 if session_not_on_or_after
        authn_statement["saml"].AuthnContext do |authn_context|
          authn_context["saml"].AuthnContextClassRef(authn_context_class_ref) if authn_context_class_ref
        end
      end
    end
  end
end
