# frozen_string_literal: true

require "saml2/authn_request"
require "saml2/entity"
require "saml2/logout_request"
require "saml2/logout_response"
require "saml2/response"
require "saml2/version"

require "saml2/engine" if defined?(Rails) && Rails::VERSION::MAJOR > 2

module SAML2
  class << self
    def config
      @config ||= { max_message_size: 1024 * 1024 }
    end
  end
end
