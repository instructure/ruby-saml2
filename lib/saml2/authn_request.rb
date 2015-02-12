require 'base64'
require 'zlib'

require 'saml2/name_id'
require 'saml2/namespaces'
require 'saml2/schemas'

module SAML2
  class AuthnRequest
    def self.decode(authnrequest)
      zstream  = Zlib::Inflate.new(-Zlib::MAX_WBITS)
      authnrequest = zstream.inflate(Base64.decode64(authnrequest))
      zstream.finish
      zstream.close
      parse(authnrequest)
    end

    def self.parse(authnrequest)
      new(Nokogiri::XML(authnrequest))
    end

    def initialize(document)
      @document = document
    end

    def valid?(sp_metadata)
      return false unless sp_metadata
      return false unless Schemas.protocol.validate(@document).empty?
      return false unless sp_metadata.issuer == issuer

      # TODO: check signature if present

      if assertion_consumer_service_url
        @acs = sp_metadata.assertion_consumer_services.find { |acs| acs.location == assertion_consumer_service_url }
      elsif assertion_consumer_service_index
        @acs = sp_metadata.assertion_consumer_services[assertion_consumer_service_index]
      else
        @acs = sp_metadata.assertion_consumer_services.default
      end
      return false unless @acs
      true
    end

    def issuer
      @issuer ||= begin
        node = @document.at_xpath('/samlp:AuthnRequest/saml:Issuer', Namespaces::ALL)
        node && node.text.strip
      end
    end

    def name_id_policy
      @name_id_policy ||= begin
        node = @document.at_xpath(@document, '/samlp:AuthnRequest/samlp:NameIDPolicy', Namespaces::ALL)
        if node
          allow_create = node['AllowCreate'].nil? ? nil : node['AllowCreate'] == 'true'
          NameID::Policy.new(allow_create, node['Format'])
        end
      end
    end

    def id
      authn_request['ID']
    end

    def protocol_binding
      authn_request['ProtocolBinding']
    end

    def assertion_consumer_service
      @acs
    end

    def assertion_consumer_service_url
      authn_request['AssertionConsumerServiceURL']
    end

    def assertion_consumer_service_index
      @acs_index ||= begin
        authn_request['AssertionConsumerServiceIndex'] &&
          authn_request['AssertionConsumerServiceIndex'].to_i
      end
    end

    def force_authn?
      authn_request['ForceAuthn']
    end

    def is_passive?
      authn_request['IsPassive']
    end

    protected
    def authn_request
      @authn_request ||= @document.at_xpath('/samlp:AuthnRequest', Namespaces::ALL)
    end
  end
end
