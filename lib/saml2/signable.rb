require 'saml2/key'

module SAML2
  module Signable
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

    def signing_key
      @signing_key ||= Key.from_xml(signature)
    end

    def signed?
      !!signature
    end

    def validate_signature(fingerprint: nil, cert: nil, verification_time: nil)
      return ["not signed"] unless signed?

      certs = Array(cert)
      # see if any given fingerprints match the certificate embedded in the XML;
      # if so, extract the certificate, and add it to the allowed certificates list
      Array(fingerprint)&.each do |fp|
        certs << signing_key.certificate if signing_key&.fingerprint == Key.format_fingerprint(fp)
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

    def valid_signature?(fingerprint: nil, cert: nil, verification_time: nil)
      validate_signature(fingerprint: fingerprint, cert: cert, verification_time: verification_time).empty?
    end
  end
end
