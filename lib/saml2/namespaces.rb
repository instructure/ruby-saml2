module SAML2
  module Namespaces
    DSIG     = "http://www.w3.org/2000/09/xmldsig#".freeze
    METADATA = "urn:oasis:names:tc:SAML:2.0:metadata".freeze
    SAML     = "urn:oasis:names:tc:SAML:2.0:assertion".freeze
    SAMLP    = "urn:oasis:names:tc:SAML:2.0:protocol".freeze
    XENC     = "http://www.w3.org/2001/04/xmlenc#".freeze
    XS       = "http://www.w3.org/2001/XMLSchema".freeze
    XSI      = "http://www.w3.org/2001/XMLSchema-instance".freeze
    X500     = "urn:oasis:names:tc:SAML:2.0:profiles:attribute:X500".freeze

    ALL = {
        'xmlns:dsig'  => DSIG,
        'xmlns:md'    => METADATA,
        'xmlns:saml'  => SAML,
        'xmlns:samlp' => SAMLP,
        'xmlns:x500'  => X500,
        'xmlns:xenc'  => XENC,
        'xmlns:xs'    => XS,
        'xmlns:xsi'   => XSI,
    }.freeze
  end
end
