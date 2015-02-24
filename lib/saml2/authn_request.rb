require 'base64'
require 'zlib'

require 'saml2/attribute_consuming_service'
require 'saml2/endpoint'
require 'saml2/name_id'
require 'saml2/namespaces'
require 'saml2/schemas'
require 'saml2/subject'

module SAML2
  class AuthnRequest
    def self.decode(authnrequest)
      begin
        zstream  = Zlib::Inflate.new(-Zlib::MAX_WBITS)
        authnrequest = zstream.inflate(Base64.decode64(authnrequest))
        zstream.finish
        zstream.close
      rescue Zlib::BufError
      end
      parse(authnrequest)
    end

    def self.parse(authnrequest)
      new(Nokogiri::XML(authnrequest))
    end

    def initialize(document)
      @document = document
    end

    def valid_schema?
      return false unless Schemas.protocol.valid?(@document)
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
      return false if protocol_binding && protocol_binding != Endpoint::Bindings::HTTP_POST
      return false if subject

      true
    end

    def resolve(service_provider)
      # TODO: check signature if present

      if assertion_consumer_service_url
        @assertion_consumer_service = service_provider.assertion_consumer_services.find { |acs| acs.location == assertion_consumer_service_url }
      else
        @assertion_consumer_service  = service_provider.assertion_consumer_services.resolve(assertion_consumer_service_index)
      end
      @attribute_consuming_service = service_provider.attribute_consuming_services.resolve(attribute_consuming_service_index)

      return false unless @assertion_consumer_service
      return false if attribute_consuming_service_index && !@attribute_consuming_service

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

    attr_reader :assertion_consumer_service, :attribute_consuming_service

    def assertion_consumer_service_url
      @document.root['AssertionConsumerServiceURL']
    end

    def assertion_consumer_service_index
      @document.root['AssertionConsumerServiceIndex'] && @document.root['AssertionConsumerServiceIndex'].to_i
    end

    def attribute_consuming_service_index
      @document.root['AttributeConsumerServiceIndex'] && @document.root['AttributeConsumerServiceIndex'].to_i
    end

    def force_authn?
      @document.root['ForceAuthn']
    end

    def passive?
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
