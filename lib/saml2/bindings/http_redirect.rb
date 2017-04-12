require 'base64'
require 'uri'
require 'zlib'

require 'saml2/bindings'
require 'saml2/message'

module SAML2
  module Bindings
    module HTTPRedirect
      URN ="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect".freeze

      class << self
        def decode(url)
          uri = begin
            URI.parse(url)
          rescue URI::InvalidURIError
            raise CorruptMessage
          end
          # TODO: validate signature if provided

          raise MissingMessage unless uri.query
          query = URI.decode_www_form(uri.query)
          base64 = query.assoc('SAMLRequest')&.last || query.assoc('SAMLResponse')&.last
          encoding = query.assoc('SAMLEncoding')&.last
          relay_state = query.assoc('RelayState')&.last
          raise MissingMessage unless base64

          raise UnsupportedEncoding if encoding && encoding != Encodings::DEFLATE

          raise MessageTooLarge if base64.bytesize > SAML2.config[:max_message_size]

          deflated = begin
            Base64.strict_decode64(base64)
          rescue ArgumentError
            raise CorruptMessage
          end

          zstream = Zlib::Inflate.new(-Zlib::MAX_WBITS)
          xml = ''
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
          [Message.parse(xml), relay_state]
        end

        def encode(message, relay_state: nil)
          result = URI.parse(message.destination)
          original_query = URI.decode_www_form(result.query) if result.query
          original_query ||= []
          # remove any SAML protocol parameters
          %w{SAMLEncoding SAMLRequest SAMLResponse RelayState SigAlg Signature}.each do |param|
            original_query.delete_if { |(k, v)| k == param }
          end

          xml = message.to_s
          zstream = Zlib::Deflate.new(Zlib::BEST_COMPRESSION, -Zlib::MAX_WBITS)
          deflated = zstream.deflate(xml, Zlib::FINISH)
          zstream.close
          base64 = Base64.strict_encode64(deflated)

          query = {}
          query[message.is_a?(Request) ? 'SAMLRequest' : 'SAMLResponse'] = base64
          query['RelayState'] = relay_state if relay_state
          # TODO: sign it

          result.query = URI.encode_www_form(original_query + query.to_a)
          result.to_s
        end
      end
    end
  end
end
