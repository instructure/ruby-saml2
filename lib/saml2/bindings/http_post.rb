require 'base64'

module SAML2
  module Bindings
    module HTTP_POST
      URN ="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST".freeze

      class << self
        def decode(post_params)
          base64 = post_params['SAMLRequest'] || post_params['SAMLResponse']
          raise MissingMessage unless base64

          raise MessageTooLarge if base64.bytesize > SAML2.config[:max_message_size]

          xml = begin
            Base64.decode64(base64)
          rescue ArgumentError
            raise CorruptMessage
          end

          message = Message.parse(xml)
          [message, post_params['RelayState']]
        end

        def encode(message, relay_state: nil)
          xml = message.to_s(pretty: false)
          key = message.is_a?(Request) ? 'SAMLRequest' : 'SAMLResponse'
          post_params = { key => Base64.encode64(xml) }
          post_params['RelayState'] = relay_state if relay_state
          post_params
        end
      end
    end
  end
end
