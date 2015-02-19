module SAML2
  class AuthnStatement
    module Classes
      INTERNET_PROTOCOL            = "urn:oasis:names:tc:SAML:2.0:ac:classes:InternetProtocol".freeze # IP address
      INTERNET_PROTOCOL_PASSWORD   = "urn:oasis:names:tc:SAML:2.0:ac:classes:InternetProtocolPassword".freeze # IP address, as well as username/password
      KERBEROS                     = "urn:oasis:names:tc:SAML:2.0:ac:classes:Kerberos".freeze
      PASSWORD                     = "urn:oasis:names:tc:SAML:2.0:ac:classes:Password".freeze # username/password, NOT over SSL
      PASSWORD_PROTECTED_TRANSPORT = "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport".freeze # username/password over SSL
      PREVIOUS_SESSION             = "urn:oasis:names:tc:SAML:2.0:ac:classes:PreviousSession".freeze # remember me
      SMARTCARD                    = "urn:oasis:names:tc:SAML:2.0:ac:classes:Smartcard".freeze
      SMARTCARD_PKI                = "urn:oasis:names:tc:SAML:2.0:ac:classes:SmartcardPKI".freeze # smartcard with a private key on it
      TLS_CLIENT                   = "urn:oasis:names:tc:SAML:2.0:ac:classes:TLSClient".freeze # SSL client certificate
      UNSPECIFIED                  = "urn:oasis:names:tc:SAML:2.0:ac:classes:unspecified".freeze
    end

    attr_accessor :authn_instant, :authn_context_class_ref

    def build(builder)
      builder['saml'].AuthnStatement('AuthnInstant' => authn_instant.iso8601) do |builder|
        builder['saml'].AuthnContext do |builder|
          builder['saml'].AuthnContextClassRef(authn_context_class_ref) if authn_context_class_ref
        end
      end
    end
  end
end
