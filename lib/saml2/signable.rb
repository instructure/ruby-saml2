# frozen_string_literal: true

require 'saml2/key'

module SAML2
  module Signable
    # @return [Nokogiri::XML::Element, nil]
    def signature
      unless instance_variable_defined?(:@signature)
        @signature = xml.at_xpath('dsig:Signature', Namespaces::ALL)
        if @signature
          signed_node = @signature.at_xpath('dsig:SignedInfo/dsig:Reference', Namespaces::ALL)['URI']
          if signed_node == ''
            @signature = nil unless xml == xml.document.root
          elsif signed_node != "##{xml['ID']}"
            # validating the schema will automatically add ID attributes, so check that first
            xml.set_id_attribute('ID') unless xml.document.get_id(xml['ID'])
            @signature = nil
          end
        end
      end
      @signature
    end

    # @return [KeyInfo, nil]
    def signing_key
      @signing_key ||= KeyInfo.from_xml(signature)
    end

    def signed?
      !!signature
    end

    # Validate the signature on this object.
    #
    # Either +fingerprint+ or +cert+ must be provided.
    #
    # @param fingerprint optional [Array<String>, String]
    #   SHA1 fingerprints of trusted certificates. If provided, they will be
    #   checked against the {#signing_key} embedded in the {#signature}, and if
    #   a match is found, the certificate embedded in the signature will be
    #   added to the list of certificates used for verifying the signature.
    # @param cert optional [Array<String>, String]
    # @return [Array<String>] An empty array on success, details of errors on failure.
    def validate_signature(fingerprint: nil, cert: nil, verification_time: nil)
      return ["not signed"] unless signed?

      certs = Array(cert)
      certs = certs.dup if certs.equal?(cert)
      # see if any given fingerprints match the certificate embedded in the XML;
      # if so, extract the certificate, and add it to the allowed certificates list
      Array(fingerprint)&.each do |fp|
        certs << signing_key.certificate if signing_key&.fingerprint == KeyInfo.format_fingerprint(fp)
      end
      certs = certs.uniq
      return ["no certificate found"] if certs.empty?

      begin
        # verify_certificates being false is hopefully a temporary thing, until I can figure
        # out how to get xmlsec to root a trust chain in a non-root certificate
        result = signature.verify_with(certs: certs, verification_time: verification_time, verify_certificates: false)
        result ? [] : ["signature does not match"]
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
    def valid_signature?(fingerprint: nil, cert: nil, verification_time: nil)
      validate_signature(fingerprint: fingerprint, cert: cert, verification_time: verification_time).empty?
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
