# frozen_string_literal: true

require 'saml2/key'

module SAML2
  module Signable
    # @return [Nokogiri::XML::Element, nil]
    def signature
      unless instance_variable_defined?(:@signature)
        @signature = xml.xpath('//dsig:Signature', Namespaces::ALL).find do |signature|
          signed_node = signature.at_xpath('dsig:SignedInfo/dsig:Reference', Namespaces::ALL)['URI']
          if signed_node == ''
            true if xml == xml.document.root
          elsif signed_node != "##{xml['ID']}"
            false
          else
            # validating the schema will automatically add ID attributes, so check that first
            xml.set_id_attribute('ID') unless xml.document.get_id(xml['ID'])
            true
          end
        end
      end
      @signature
    end

    # @return [KeyInfo, nil]
    def signing_key
      unless instance_variable_defined?(:@signing_key)
        # don't use `... if signature.at_xpath(...)` - we need to make sure we assign the nil
        @signing_key = signature.at_xpath('dsig:KeyInfo', Namespaces::ALL) ? KeyInfo.from_xml(signature) : nil
      end
      @signing_key
    end

    def signed?
      !!signature
    end

    # Validate the signature on this object.
    #
    # At least one of +key+, +fingerprint+ or +cert+ must be provided.
    #
    # @param key optional [String, OpenSSL::PKey::PKey]
    #   The exact public key to use. +fingerprint+ and +cert+ are ignored.
    # @param fingerprint optional [Array<String>, String]
    #   SHA1 fingerprints of trusted certificates. If provided, they will be
    #   checked against the {#signing_key} embedded in the {#signature}, and if
    #   a match is found, the certificate embedded in the signature will be
    #   added to the list of certificates used for verifying the signature.
    # @param cert optional [Array<String>, String]
    #   A single or array of trusted certificates. If provided, they will be
    #   check against the {#signing_key} embedded in the {#signature}, and if
    #   a match of public keys only is found, that key will be considered trusted
    #   and used to verify the signature.
    # @return [Array<String>] An empty array on success, details of errors on failure.
    def validate_signature(key: nil,
                           fingerprint: nil,
                           cert: nil)
      return ["not signed"] unless signed?

      certs = Array(cert)
      certs = certs.dup if certs.equal?(cert)
      # see if any given fingerprints match the certificate embedded in the XML;
      # if so, extract the certificate, and add it to the allowed certificates list
      Array(fingerprint).each do |fp|
        certs << signing_key.certificate if signing_key&.fingerprint == SAML2::KeyInfo.format_fingerprint(fp)
      end
      certs = certs.uniq

      trusted_keys = certs.map do |cert|
        cert = cert.is_a?(String) ? OpenSSL::X509::Certificate.new(cert) : cert
        cert.public_key.to_s
      end
      if signing_key&.certificate && trusted_keys.include?(signing_key.certificate.public_key.to_s)
        key ||= signing_key.certificate.public_key.to_s
      end
      # signature doesn't say who signed it. hope and pray it's with the only certificate
      # we know about
      if signing_key.nil? && key.nil? && trusted_keys.length == 1
        key = trusted_keys.first
      end

      return ["no trusted signing key found"] if key.nil?

      begin
        result = signature.verify_with(key: key)
        result ? [] : ["signature is invalid"]
      rescue XMLSec::VerificationError => e
        [e.message]
      end
    end

    # Check if the signature on this object is valid.
    #
    # Either +fingerprint+ or +cert+ must be provided.
    #
    # @param (see #validate_signature)
    # @return [Boolean]
    def valid_signature?(fingerprint: nil, cert: nil)
      validate_signature(fingerprint: fingerprint, cert: cert).empty?
    end

    # Sign this object.
    #
    # @param x509_certificate [String]
    #   The certificate corresponding to +private_key+, to be embedded in the
    #   signature.
    # @param private_key [String]
    #   The key to use to sign.
    # @param algorithm_name [Symbol]
    # @return [self]
    def sign(x509_certificate, private_key, algorithm_name = :sha256)
      to_xml

      xml = @document.root
      xml.set_id_attribute('ID')
      xml.sign!(cert: x509_certificate, key: private_key, digest_alg: algorithm_name.to_s, signature_alg: "rsa-#{algorithm_name}", uri: "##{id}")
      # the Signature element must be the first element
      signature = xml.at_xpath("dsig:Signature", Namespaces::ALL)
      xml.children.first.add_previous_sibling(signature)

      self
    end
  end
end
