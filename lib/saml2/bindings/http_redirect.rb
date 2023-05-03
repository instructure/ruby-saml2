# frozen_string_literal: true

require "base64"
require "uri"
require "zlib"

require "saml2/bindings"
require "saml2/message"

module SAML2
  module Bindings
    module HTTPRedirect
      URN = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"

      module SigAlgs
        DSA_SHA1 = "http://www.w3.org/2000/09/xmldsig#dsa-sha1"
        RSA_SHA1 = "http://www.w3.org/2000/09/xmldsig#rsa-sha1"
        RSA_SHA256 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"

        RECOGNIZED = [DSA_SHA1, RSA_SHA1, RSA_SHA256].freeze
      end

      class << self
        # Decode, validate signature, and parse a compressed and Base64 encoded
        # SAML message.
        #
        # A signature, if present, will be verified only if +public_key+ is
        # passed.
        #
        # @param url [String]
        #   The full URL to decode. Will check for both +SAMLRequest+ and
        #   +SAMLResponse+ params.
        # @param public_key optional [Array<OpenSSL::PKey>, OpenSSL::PKey, Proc]
        #   Keys to use to check the signature. If a +Proc+ is provided, it is
        #   called with the parsed {Message}, and the +SigAlg+ in order for the
        #   caller to find an appropriate key based on the {Message}'s issuer.
        # @param public_key_used optional [Proc]
        #   Is called with the actual key that was used to validate the
        #   signature.
        # @return [[Message, String]]
        #   The Message and the RelayState.
        # @raise [UnsignedMessage] If a public_key is provided, but the message
        #   is not signed.
        # @yield [message, sig_alg]
        #   The same as a +Proc+ provided to +public_key+. Deprecated.
        def decode(url, public_key: nil, public_key_used: nil)
          uri = begin
            URI.parse(url)
          rescue URI::InvalidURIError
            raise CorruptMessage
          end

          raise MissingMessage unless uri.query

          query = URI.decode_www_form(uri.query)
          base64 = query.assoc("SAMLRequest")&.last
          if base64
            message_param = "SAMLRequest"
          else
            base64 = query.assoc("SAMLResponse")&.last
            message_param = "SAMLResponse"
          end
          encoding = query.assoc("SAMLEncoding")&.last
          relay_state = query.assoc("RelayState")&.last
          signature = query.assoc("Signature")&.last
          sig_alg = query.assoc("SigAlg")&.last
          raise MissingMessage unless base64

          raise UnsupportedEncoding if encoding && encoding != Encodings::DEFLATE

          raise MessageTooLarge if base64.bytesize > SAML2.config[:max_message_size]

          deflated = begin
            Base64.strict_decode64(base64)
          rescue ArgumentError
            raise CorruptMessage
          end

          zstream = Zlib::Inflate.new(-Zlib::MAX_WBITS)
          xml = +""
          begin
            # do it in 1K slices, so we can protect against bombs
            (0..deflated.bytesize / 1024).each do |i|
              xml.concat(zstream.inflate(deflated.byteslice(i * 1024, 1024)))
              raise MessageTooLarge if xml.bytesize > SAML2.config[:max_message_size]
            end
            xml.concat(zstream.finish)
            raise MessageTooLarge if xml.bytesize > SAML2.config[:max_message_size]
          rescue Zlib::DataError, Zlib::BufError
            raise CorruptMessage
          end

          zstream.close
          message = Message.parse(xml)
          # if a block is provided, it's to fetch the proper certificate
          # based on the contents of the message
          public_key ||= yield(message, sig_alg) if block_given?
          public_key = public_key.call(message, sig_alg) if public_key.is_a?(Proc)
          if public_key
            raise UnsignedMessage unless signature
            raise UnsupportedSignatureAlgorithm unless SigAlgs::RECOGNIZED.include?(sig_alg)

            begin
              signature = Base64.strict_decode64(signature)
            rescue ArgumentError
              raise CorruptMessage
            end

            base_string = find_raw_query_param(uri.query, message_param)
            base_string << "&" << find_raw_query_param(uri.query, "RelayState") if relay_state
            base_string << "&" << find_raw_query_param(uri.query, "SigAlg")

            valid_signature = false
            # there could be multiple certificates to try
            Array(public_key).each do |key|
              hash = ((sig_alg == SigAlgs::RSA_SHA256) ? OpenSSL::Digest::SHA256 : OpenSSL::Digest::SHA1)
              next unless key.verify(hash.new, signature, base_string)

              # notify the caller which certificate was used
              public_key_used&.call(key)
              valid_signature = true
              break
            end
            raise InvalidSignature unless valid_signature
          end
          [message, relay_state]
        end

        # Encode a SAML message into Base64, compressed query params.
        #
        # @param message [Message]
        #   Note that the base URI is taken from {Message#destination}.
        # @param relay_state optional [String]
        # @param private_key optional [OpenSSL::PKey::RSA]
        #   A key to use to sign the encoded message.
        # @param sig_alg optional [String]
        #   The signing algorithm to use. Defaults to RSA-SHA1, as it's the
        #   most compatible, and explicitly mentioned in the SAML specs, but
        #   you may want to use RSA-SHA256. Values must come from {SigAlgs}.
        # @return [String]
        #   The full URI to redirect to, including +RelayState+, and
        #   +SAMLRequest+ vs. +SAMLResponse+ chosen appropriately, and
        #   +Signature+ + +SigAlg+ query params if signing.
        def encode(message, relay_state: nil, private_key: nil, sig_alg: SigAlgs::RSA_SHA1)
          result = URI.parse(message.destination)
          original_query = URI.decode_www_form(result.query) if result.query
          original_query ||= []
          # remove any SAML protocol parameters
          %w[SAMLEncoding SAMLRequest SAMLResponse RelayState SigAlg Signature].each do |param|
            original_query.delete_if { |(k, _v)| k == param }
          end

          xml = message.to_s(pretty: false)
          zstream = Zlib::Deflate.new(Zlib::BEST_COMPRESSION, -Zlib::MAX_WBITS)
          deflated = zstream.deflate(xml, Zlib::FINISH)
          zstream.close
          base64 = Base64.strict_encode64(deflated)

          query = []
          query << [message.is_a?(Request) ? "SAMLRequest" : "SAMLResponse", base64]
          query << ["RelayState", relay_state] if relay_state
          if private_key
            unless SigAlgs::RECOGNIZED.include?(sig_alg)
              raise ArgumentError,
                    "Unsupported signature algorithm #{sig_alg}"
            end

            query << ["SigAlg", sig_alg]
            base_string = URI.encode_www_form(query)
            hash = ((sig_alg == SigAlgs::RSA_SHA256) ? OpenSSL::Digest::SHA256 : OpenSSL::Digest::SHA1)
            signature = private_key.sign(hash.new, base_string)
            query << ["Signature", Base64.strict_encode64(signature)]
          end

          result.query = URI.encode_www_form(original_query + query)
          result.to_s
        end

        private

        # we need to find the param, and return it still encoded from the URL
        def find_raw_query_param(query, param)
          start = query.index(param)
          finish = (query.index("&", start + param.length + 1) || 0) - 1
          query[start..finish]
        end
      end
    end
  end
end
