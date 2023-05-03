# frozen_string_literal: true

require "saml2/attribute"
require "saml2/sso"

module SAML2
  class IdentityProvider < SSO
    # @return [Boolean, nil]
    attr_writer :want_authn_requests_signed
    attr_writer :single_sign_on_services, :attribute_profiles, :attributes

    def initialize
      super
      @want_authn_requests_signed = nil
      @single_sign_on_services = []
      @attribute_profiles = []
      @attributes = []
    end

    # (see Base#from_xml)
    def from_xml(node)
      super
      remove_instance_variable(:@want_authn_requests_signed)
      @single_sign_on_services = nil
      @attribute_profiles = nil
      @attributes = nil
    end

    # @return [Boolean, nil]
    def want_authn_requests_signed?
      unless instance_variable_defined?(:@want_authn_requests_signed)
        @want_authn_requests_signed = xml["WantAuthnRequestsSigned"] && xml["WantAuthnRequestsSigned"] == "true"
      end
      @want_authn_requests_signed
    end

    # @return [Array<Endpoint>]
    def single_sign_on_services
      @single_sign_on_services ||= load_object_array(xml, "md:SingleSignOnService", Endpoint)
    end

    # @return [Array<String>]
    def attribute_profiles
      @attribute_profiles ||= load_string_array(xml, "md:AttributeProfile")
    end

    # @return [Array<Attribute>]
    def attributes
      @attributes ||= load_object_array(xml, "saml:Attribute", Attribute)
    end

    # (see Base#build)
    def build(builder)
      builder["md"].IDPSSODescriptor do |idp_sso_descriptor|
        super(idp_sso_descriptor)

        unless want_authn_requests_signed?.nil?
          idp_sso_descriptor.parent["WantAuthnRequestsSigned"] =
            want_authn_requests_signed?
        end

        single_sign_on_services.each do |sso|
          sso.build(idp_sso_descriptor, "SingleSignOnService")
        end

        attribute_profiles.each do |ap|
          idp_sso_descriptor["md"].AttributeProfile(ap)
        end

        attributes.each do |attr|
          attr.build(idp_sso_descriptor)
        end
      end
    end
  end
end
