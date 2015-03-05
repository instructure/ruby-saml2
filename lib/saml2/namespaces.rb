module SAML2
  module Namespaces
    DSIG     = "http://www.w3.org/2000/09/xmldsig#".freeze
    METADATA = "urn:oasis:names:tc:SAML:2.0:metadata".freeze
    SAML     = "urn:oasis:names:tc:SAML:2.0:assertion".freeze
    SAMLP    = "urn:oasis:names:tc:SAML:2.0:protocol".freeze
    XENC     = "http://www.w3.org/2001/04/xmlenc#".freeze
    XSI      = "http://www.w3.org/2001/XMLSchema-instance".freeze
    X500     = "urn:oasis:names:tc:SAML:2.0:profiles:attribute:X500".freeze

    ALL = {
        'dsig'  => DSIG,
        'md'    => METADATA,
        'saml'  => SAML,
        'samlp' => SAMLP,
        'x500'  => X500,
        'xenc'  => XENC,
        'xsi'   => XSI
    }.freeze
  end
end
