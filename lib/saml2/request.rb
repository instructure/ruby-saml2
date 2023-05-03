# frozen_string_literal: true

require "saml2/message"
require "saml2/name_id"
require "saml2/namespaces"

module SAML2
  # @abstract
  class Request < Message
  end
end
