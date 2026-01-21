# frozen_string_literal: true

require "saml2/base"

module SAML2
  class AuthnStatement < Base
    # @see https://docs.oasis-open.org/security/saml/v2.0/saml-authn-context-2.0-os.pdf
    module Classes
      INTERNET_PROTOCOL = "urn:oasis:names:tc:SAML:2.0:ac:classes:InternetProtocol"
      INTERNET_PROTOCOL_PASSWORD = "urn:oasis:names:tc:SAML:2.0:ac:classes:InternetProtocolPassword"
      KERBEROS = "urn:oasis:names:tc:SAML:2.0:ac:classes:Kerberos"
      MOBILE_ONE_FACTOR_CONTRACT = "urn:oasis:names:tc:SAML:2.0:ac:classes:MobileOneFactorContract"
      MOBILE_ONE_FACTOR_UNREGISTERED = "urn:oasis:names:tc:SAML:2.0:ac:classes:MobileOneFactorUnregistered"
      MOBILE_TWO_FACTOR_CONTRACT = "urn:oasis:names:tc:SAML:2.0:ac:classes:MobileTwoFactorContract"
      MOBILE_TWO_FACTOR_UNREGISTERED = "urn:oasis:names:tc:SAML:2.0:ac:classes:MobileTwoFactorUnregistered"
      PASSWORD = "urn:oasis:names:tc:SAML:2.0:ac:classes:Password"
      PASSWORD_PROTECTED_TRANSPORT = "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport"
      PGP = "urn:oasis:names:tc:SAML:2.0:ac:classes:PGP"
      PREVIOUS_SESSION = "urn:oasis:names:tc:SAML:2.0:ac:classes:PreviousSession"
      SMARTCARD = "urn:oasis:names:tc:SAML:2.0:ac:classes:Smartcard"
      SMARTCARD_PKI = "urn:oasis:names:tc:SAML:2.0:ac:classes:SmartcardPKI"
      SOFTWARE_PKI = "urn:oasis:names:tc:SAML:2.0:ac:classes:SoftwarePKI"
      SPKI = "urn:oasis:names:tc:SAML:2.0:ac:classes:SPKI"
      SECURE_REMOTE_PASSWORD = "urn:oasis:names:tc:SAML:2.0:ac:classes:SecureRemotePassword"
      TELEPHONY = "urn:oasis:names:tc:SAML:2.0:ac:classes:Telephony"
      TELEPHONY_AUTHENTICATED = "urn:oasis:names:tc:SAML:2.0:ac:classes:AuthenticatedTelephony"
      TELEPHONHY_NOMAD = "urn:oasis:names:tc:SAML:2.0:ac:classes:NomadTelephony"
      TELEPHONY_PERSONALIZED = "urn:oasis:names:tc:SAML:2.0:ac:classes:PersonalTelephony"
      TIME_SYNC_TOKEN = "urn:oasis:names:tc:SAML:2.0:ac:classes:TimeSyncToken"
      TLS_CLIENT = "urn:oasis:names:tc:SAML:2.0:ac:classes:TLSClient"
      X509 = "urn:oasis:names:tc:SAML:2.0:ac:classes:X509"
      XMLDSIG = "urn:oasis:names:tc:SAML:2.0:ac:classes:XMLDSig"
      UNSPECIFIED = "urn:oasis:names:tc:SAML:2.0:ac:classes:unspecified"

      # @see https://refeds.org/profile/mfa
      REFEDS_MFA = "https://refeds.org/profile/mfa"
      # @see https://refeds.org/profile/sfa
      REFEDS_SFA = "https://refeds.org/profile/sfa"

      # @see https://learn.microsoft.com/en-us/entra/identity/authentication/how-to-mfa-expected-inbound-assertions
      MICROSOFT_MULTIPLE_AUTHN = "http://schemas.microsoft.com/claims/multipleauthn"
      # @see https://learn.microsoft.com/en-us/entra/identity/authentication/how-to-mfa-expected-inbound-assertions
      MICROSOFT_WIA_OR_MULTI_AUTHN = "http://schemas.microsoft.com/claims/wiaormultiauthn"
      # @see https://learn.microsoft.com/en-us/entra/identity-platform/single-sign-on-saml-protocol#requestedauthncontext
      MICROSOFT_WINDOWS = "urn:federation:authentication:windows"
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
