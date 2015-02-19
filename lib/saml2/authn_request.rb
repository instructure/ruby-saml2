require 'base64'
require 'zlib'

require 'saml2/name_id'
require 'saml2/namespaces'
require 'saml2/schemas'
require 'saml2/subject'

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

    def valid_schema?
      return false unless Schemas.protocol.validate(@document).empty?
      # Check for the correct root element
      return false unless @document.at_xpath('/samlp:AuthnRequest', Namespaces::ALL)

      true
    end

    def valid_web_browser_sso_profile?
      return false unless issuer
      return false if issuer.format && issuer.format != NameID::Format::ENTITY

      true
    end

    def valid_interoperable_profile?
      # It's a subset of Web Browser SSO profile
      return false unless valid_web_browser_sso_profile?

      return false unless assertion_consumer_service_url
      return false if protocol_binding && protocol_binding != AssertionConsumerService::Bindings::HTTP_POST
      return false if subject

      true
    end

    def resolve(sp_metadata)
      return false if issuer && sp_metadata.entity_id != issuer.id

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
      @issuer ||= NameID.from_xml(@document.root.at_xpath('saml:Issuer', Namespaces::ALL))
    end

    def name_id_policy
      @name_id_policy ||= NameID::Policy.from_xml(@document.root.at_xpath('samlp:NameIDPolicy', Namespaces::ALL))
    end

    def id
      @document.root['ID']
    end

    def assertion_consumer_service
      @acs
    end

    def assertion_consumer_service_url
      @document.root['AssertionConsumerServiceURL']
    end

    def assertion_consumer_service_index
      @acs_index ||= begin
        @document.root['AssertionConsumerServiceIndex'] &&
            @document.root['AssertionConsumerServiceIndex'].to_i
      end
    end

    def force_authn?
      @document.root['ForceAuthn']
    end

    def is_passive?
      @document.root['IsPassive']
    end

    def protocol_binding
      @document.root['ProtocolBinding']
    end

    def subject
      @subject ||= Subject.from_xml(@document.at_xpath('saml:Subject', Namespaces::ALL))
    end
  end
end
