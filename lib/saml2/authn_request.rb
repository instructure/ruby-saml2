require 'base64'
require 'zlib'

require 'saml2/attribute_consuming_service'
require 'saml2/bindings/http_redirect'
require 'saml2/endpoint'
require 'saml2/name_id'
require 'saml2/namespaces'
require 'saml2/request'
require 'saml2/requested_authn_context'
require 'saml2/schemas'
require 'saml2/subject'

module SAML2
  class AuthnRequest < Request
    # deprecated; takes _just_ the SAMLRequest parameter's value
    def self.decode(authnrequest)
      result, _relay_state = Bindings::HTTPRedirect.decode("http://host/?SAMLRequest=#{CGI.escape(authnrequest)}")
      return nil unless result.is_a?(AuthnRequest)
      result
    rescue CorruptMessage
      AuthnRequest.from_xml(Nokogiri::XML('<xml></xml>').root)
    end

    attr_writer :assertion_consumer_service_index,
                :assertion_consumer_service_url,
                :attribute_consuming_service_index,
                :force_authn,
                :name_id_policy,
                :passive,
                :protocol_binding
    attr_accessor :requested_authn_context

    def self.initiate(issuer, identity_provider = nil,
        assertion_consumer_service: nil,
        service_provider: nil)
      authn_request = new
      authn_request.issuer = issuer
      authn_request.destination = identity_provider.single_sign_on_services.first.location if identity_provider
      authn_request.name_id_policy = NameID::Policy.new(true, NameID::Format::UNSPECIFIED)
      assertion_consumer_service ||= service_provider.assertion_consumer_services.default if service_provider
      if assertion_consumer_service
        authn_request.protocol_binding = assertion_consumer_service.binding
        authn_request.assertion_consumer_service_url = assertion_consumer_service.location
      end
      authn_request
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

    def name_id_policy
      if xml && !instance_variable_defined?(:@name_id_policy)
        @name_id_policy = NameID::Policy.from_xml(xml.at_xpath('samlp:NameIDPolicy', Namespaces::ALL))
      end
      @name_id_policy
    end

    attr_reader :assertion_consumer_service, :attribute_consuming_service

    def assertion_consumer_service_index
      if xml && !instance_variable_defined?(:@assertion_consumer_service_index)
        @assertion_consumer_service_index = xml['AssertionConsumerServiceIndex']&.to_i
      end
      @assertion_consumer_service_index
    end

    def assertion_consumer_service_url
      if xml && !instance_variable_defined?(:@assertion_consumer_service_url)
        @assertion_consumer_service_url = xml['AssertionConsumerServiceURL']
      end
      @assertion_consumer_service_url
    end

    def attribute_consuming_service_index
      if xml && !instance_variable_defined?(:@attribute_consuming_service_index)
        @attribute_consuming_service_index = xml['AttributeConsumingServiceIndex']&.to_i
      end
      @attribute_consuming_service_index
    end

    def force_authn?
      if xml && !instance_variable_defined?(:@force_authn)
        @force_authn = xml['ForceAuthn']&.== 'true'
      end
      @force_authn
    end

    def passive?
      if xml && !instance_variable_defined?(:@passive)
        @passive = xml['IsPassive']&.== 'true'
      end
      @passive
    end

    def protocol_binding
      if xml && !instance_variable_defined?(:@protocol_binding)
        @protocol_binding = xml['ProtocolBinding']
      end
      @protocol_binding
    end

    def subject
      if xml && !instance_variable_defined?(:@subject)
        @subject = Subject.from_xml(xml.at_xpath('saml:Subject', Namespaces::ALL))
      end
      @subject
    end

    def build(builder)
      builder['samlp'].AuthnRequest(
          'xmlns:samlp' => Namespaces::SAMLP,
          'xmlns:saml' => Namespaces::SAML
      ) do |authn_request|
        super(authn_request)

        authn_request.parent['AssertionConsumerServiceIndex'] = assertion_consumer_service_index if assertion_consumer_service_index
        authn_request.parent['AssertionConsumerServiceURL'] = assertion_consumer_service_url if assertion_consumer_service_url
        authn_request.parent['AttributeConsumingServiceIndex'] = attribute_consuming_service_index if attribute_consuming_service_index
        authn_request.parent['ForceAuthn'] = force_authn? unless force_authn?.nil?
        authn_request.parent['IsPassive'] = passive? unless passive?.nil?
        authn_request.parent['ProtocolBinding'] = protocol_binding if protocol_binding

        subject.build(authn_request) if subject
        name_id_policy.build(authn_request) if name_id_policy
        requested_authn_context.build(authn_request) if requested_authn_context
      end
    end
  end
end
