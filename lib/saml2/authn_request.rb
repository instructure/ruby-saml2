# frozen_string_literal: true

require "base64"
require "zlib"

require "saml2/attribute_consuming_service"
require "saml2/bindings/http_redirect"
require "saml2/endpoint"
require "saml2/name_id"
require "saml2/namespaces"
require "saml2/request"
require "saml2/requested_authn_context"
require "saml2/schemas"
require "saml2/subject"

module SAML2
  class AuthnRequest < Request
    attr_writer :assertion_consumer_service_index,
                :assertion_consumer_service_url,
                :attribute_consuming_service_index,
                :name_id_policy,
                :protocol_binding
    # @return [Boolean, nil]
    attr_writer :force_authn, :passive
    # @return [RequestedAuthnContext, nil]
    attr_accessor :requested_authn_context

    # Initiate a SAML SSO flow, from a service provider to an identity
    # provider.
    # @todo go over these params, and use kwargs. Maybe pass Entity instead
    #   of ServiceProvider.
    # @param issuer [NameID]
    # @param identity_provider [IdentityProvider]
    # @param assertion_consumer_service [Endpoint::Indexed]
    # @param service_provider [ServiceProvider]
    # @return [AuthnRequest]
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

    # @see https://docs.oasis-open.org/security/saml/v2.0/saml-profiles-2.0-os.pdf section 4.1
    def valid_web_browser_sso_profile?
      return false unless issuer
      return false if issuer.format && issuer.format != NameID::Format::ENTITY

      true
    end

    # @see https://saml2int.org/profile/current/#section82
    def valid_interoperable_profile?
      # It's a subset of Web Browser SSO profile
      return false unless valid_web_browser_sso_profile?

      return false unless assertion_consumer_service_url
      return false if protocol_binding && protocol_binding != Bindings::HTTP_POST::URN
      return false if subject

      true
    end

    # Populate {#assertion_consumer_service} and {#attribute_consuming_service}
    # attributes.
    #
    # Given {ServiceProvider} metadata, resolve the index/urls in this object to actual
    # objects.
    #
    # @param service_provider [ServiceProvider]
    # @return [Boolean]
    def resolve(service_provider)
      # TODO: check signature if present

      @assertion_consumer_service =
        if assertion_consumer_service_url
          service_provider.assertion_consumer_services.find do |acs|
            acs.location == assertion_consumer_service_url
          end
        else
          service_provider.assertion_consumer_services.resolve(assertion_consumer_service_index)
        end
      @attribute_consuming_service =
        service_provider.attribute_consuming_services.resolve(attribute_consuming_service_index)

      return false unless @assertion_consumer_service
      return false if attribute_consuming_service_index && !@attribute_consuming_service

      true
    end

    # @return [NameID::Policy, nil]
    def name_id_policy
      if xml && !instance_variable_defined?(:@name_id_policy)
        @name_id_policy = NameID::Policy.from_xml(xml.at_xpath("samlp:NameIDPolicy", Namespaces::ALL))
      end
      @name_id_policy
    end

    # Must call {#resolve} before accessing.
    # @return [AssertionConsumerService, nil]
    attr_reader :assertion_consumer_service
    # Must call {#resolve} before accessing.
    # @return [AttributeConsumingService, nil]
    attr_reader :attribute_consuming_service

    # @return [Integer, nil]
    def assertion_consumer_service_index
      if xml && !instance_variable_defined?(:@assertion_consumer_service_index)
        @assertion_consumer_service_index = xml["AssertionConsumerServiceIndex"]&.to_i
      end
      @assertion_consumer_service_index
    end

    # @return [String, nil]
    def assertion_consumer_service_url
      if xml && !instance_variable_defined?(:@assertion_consumer_service_url)
        @assertion_consumer_service_url = xml["AssertionConsumerServiceURL"]
      end
      @assertion_consumer_service_url
    end

    # @return [Integer, nil]
    def attribute_consuming_service_index
      if xml && !instance_variable_defined?(:@attribute_consuming_service_index)
        @attribute_consuming_service_index = xml["AttributeConsumingServiceIndex"]&.to_i
      end
      @attribute_consuming_service_index
    end

    # @return [true, false, nil]
    def force_authn?
      @force_authn = xml["ForceAuthn"]&.== "true" if xml && !instance_variable_defined?(:@force_authn)
      @force_authn
    end

    # @return [true, false, nil]
    def passive?
      @passive = xml["IsPassive"]&.== "true" if xml && !instance_variable_defined?(:@passive)
      @passive
    end

    # @return [String, nil]
    def protocol_binding
      @protocol_binding = xml["ProtocolBinding"] if xml && !instance_variable_defined?(:@protocol_binding)
      @protocol_binding
    end

    # @return [Subject, nil]
    def subject
      if xml && !instance_variable_defined?(:@subject)
        @subject = Subject.from_xml(xml.at_xpath("saml:Subject", Namespaces::ALL))
      end
      @subject
    end

    # (see Base#build)
    def build(builder)
      builder["samlp"].AuthnRequest(
        "xmlns:samlp" => Namespaces::SAMLP,
        "xmlns:saml" => Namespaces::SAML
      ) do |authn_request|
        super(authn_request)

        if assertion_consumer_service_index
          authn_request.parent["AssertionConsumerServiceIndex"] =
            assertion_consumer_service_index
        end
        if assertion_consumer_service_url
          authn_request.parent["AssertionConsumerServiceURL"] =
            assertion_consumer_service_url
        end
        if attribute_consuming_service_index
          authn_request.parent["AttributeConsumingServiceIndex"] =
            attribute_consuming_service_index
        end
        authn_request.parent["ForceAuthn"] = force_authn? unless force_authn?.nil?
        authn_request.parent["IsPassive"] = passive? unless passive?.nil?
        authn_request.parent["ProtocolBinding"] = protocol_binding if protocol_binding

        subject&.build(authn_request)
        name_id_policy&.build(authn_request)
        requested_authn_context&.build(authn_request)
      end
    end
  end
end
