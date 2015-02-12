require 'saml2/authn_request'
require 'saml2/response'
require 'saml2/sp_metadata'
require 'saml2/version'

require 'saml2/engine' if defined?(::Rails) && Rails::VERSION::MAJOR > 2

module SAML2
end
