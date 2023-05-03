# frozen_string_literal: true

module SAML2
  module Namespaces
    DSIG     = "http://www.w3.org/2000/09/xmldsig#"
    METADATA = "urn:oasis:names:tc:SAML:2.0:metadata"
    SAML     = "urn:oasis:names:tc:SAML:2.0:assertion"
    SAMLP    = "urn:oasis:names:tc:SAML:2.0:protocol"
    XENC     = "http://www.w3.org/2001/04/xmlenc#"
    XS       = "http://www.w3.org/2001/XMLSchema"
    XSI      = "http://www.w3.org/2001/XMLSchema-instance"
    X500     = "urn:oasis:names:tc:SAML:2.0:profiles:attribute:X500"

    ALL = {
      "xmlns:dsig" => DSIG,
      "xmlns:md" => METADATA,
      "xmlns:saml" => SAML,
      "xmlns:samlp" => SAMLP,
      "xmlns:x500" => X500,
      "xmlns:xenc" => XENC,
      "xmlns:xs" => XS,
      "xmlns:xsi" => XSI
    }.freeze
  end
end
