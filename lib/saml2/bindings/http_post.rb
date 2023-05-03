# frozen_string_literal: true

require "base64"

module SAML2
  module Bindings
    module HTTP_POST # rubocop:disable Naming/ClassAndModuleCamelCase
      URN = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"

      class << self
        # Decode and parse a Base64 encoded SAML message.
        #
        # @param post_params [Hash<String => String>]
        #   The POST params. Will check for both +SAMLRequest+ and
        #   +SAMLResponse+ params.
        # @return [[Message, String]]
        #   The Message and the RelayState.
        def decode(post_params)
          base64 = post_params["SAMLRequest"] || post_params["SAMLResponse"]
          raise MissingMessage unless base64

          raise MessageTooLarge if base64.bytesize > SAML2.config[:max_message_size]

          xml = begin
            Base64.decode64(base64)
          rescue ArgumentError
            raise CorruptMessage
          end

          message = Message.parse(xml)
          [message, post_params["RelayState"]]
        end

        # Encode a SAML message into Base64 POST params.
        #
        # @param message [Message]
        # @param relay_state optional [String]
        # @return [Hash<String => String>]
        #   The POST params, including +RelayState+, and +SAMLRequest+ vs.
        #   +SAMLResponse+ chosen appropriately.
        def encode(message, relay_state: nil)
          xml = message.to_s(pretty: false)
          key = message.is_a?(Request) ? "SAMLRequest" : "SAMLResponse"
          post_params = { key => Base64.encode64(xml) }
          post_params["RelayState"] = relay_state if relay_state
          post_params
        end
      end
    end
  end
end
