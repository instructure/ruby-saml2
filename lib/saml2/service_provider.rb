# frozen_string_literal: true

require "nokogiri"

require "saml2/endpoint"
require "saml2/sso"

module SAML2
  class ServiceProvider < SSO
    attr_writer :authn_requests_signed, :want_assertions_signed

    def initialize
      super
      @authn_requests_signed = nil
      @want_assertions_signed = nil
      @assertion_consumer_services = Endpoint::Indexed::Array.new
      @attribute_consuming_services = AttributeConsumingService::Array.new
    end

    # (see Base#from_xml)
    def from_xml(node)
      super
      remove_instance_variable(:@authn_requests_signed)
      remove_instance_variable(:@want_assertions_signed)
      @assertion_consumer_services = nil
      @attribute_consuming_services = nil
    end

    # @return [Boolean, nil]
    def authn_requests_signed?
      unless instance_variable_defined?(:@authn_requests_signed)
        @authn_requests_signed = xml["AuthnRequestsSigned"] && xml["AuthnRequestsSigned"] == "true"
      end
      @authn_requests_signed
    end

    # @return [Boolean, nil]
    def want_assertions_signed?
      unless instance_variable_defined?(:@want_assertions_signed)
        @want_assertions_signed = xml["WantAssertionsSigned"] && xml["WantAssertionsSigned"] == "true"
      end
      @want_assertions_signed
    end

    # @return [Endpoint::Indexed::Array]
    def assertion_consumer_services
      @assertion_consumer_services ||= begin
        nodes = xml.xpath("md:AssertionConsumerService", Namespaces::ALL)
        Endpoint::Indexed::Array.from_xml(nodes)
      end
    end

    # @return [AttributeConsumingService::Array]
    def attribute_consuming_services
      @attribute_consuming_services ||= begin
        nodes = xml.xpath("md:AttributeConsumingService", Namespaces::ALL)
        AttributeConsumingService::Array.from_xml(nodes)
      end
    end

    # (see Base#build)
    def build(builder)
      builder["md"].SPSSODescriptor do |sp_sso_descriptor|
        super(sp_sso_descriptor)

        sp_sso_descriptor.parent["AuthnRequestsSigned"] = authn_requests_signed? unless authn_requests_signed?.nil?
        sp_sso_descriptor.parent["WantAssertionsSigned"] = want_assertions_signed? unless authn_requests_signed?.nil?

        assertion_consumer_services.each do |acs|
          acs.build(sp_sso_descriptor, "AssertionConsumerService")
        end

        attribute_consuming_services.each do |acs|
          acs.build(sp_sso_descriptor)
        end
      end
    end
  end
end
