module SAML2
  module Namespaces
    DSIG = "http://www.w3.org/2000/09/xmldsig#".freeze
    METADATA = "urn:oasis:names:tc:SAML:2.0:metadata".freeze
    SAML = "urn:oasis:names:tc:SAML:2.0:assertion".freeze
    SAMLP = "urn:oasis:names:tc:SAML:2.0:protocol".freeze

    ALL = {
        'dsig' => DSIG,
        'md' => METADATA,
        'saml' => SAML,
        'samlp' => SAMLP,
    }.freeze
  end
end
