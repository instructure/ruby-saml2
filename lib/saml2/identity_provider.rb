require 'saml2/attribute'
require 'saml2/sso'

module SAML2
  class IdentityProvider < SSO
    attr_writer :want_authn_requests_signed, :single_sign_on_services, :attribute_profiles, :attributes

    def initialize
      super
      @want_authn_requests_signed = nil
      @single_sign_on_services = []
      @attribute_profiles = []
      @attributes = []
    end

    def from_xml(node)
      super
      remove_instance_variable(:@want_authn_requests_signed)
      @single_sign_on_services = nil
      @attribute_profiles = nil
      @attributes = nil
    end

    def want_authn_requests_signed?
      unless instance_variable_defined?(:@want_authn_requests_signed)
        @want_authn_requests_signed = @root['WantAuthnRequestsSigned'] && @root['WantAuthnRequestsSigned'] == 'true'
      end
      @want_authn_requests_signed
    end

    def single_sign_on_services
      @single_sign_on_services ||= load_object_array(@root, 'md:SingleSignOnService', Endpoint)
    end

    def attribute_profiles
      @attribute_profiles ||= load_string_array(@root, 'md:AttributeProfile')
    end

    def attributes
      @attributes ||= load_object_array(@root, 'saml:Attribute', Attribute)
    end

    def build(builder)
      builder['md'].IDPSSODescriptor do |builder|
        super(builder)

        builder['WantAuthnRequestsSigned'] = want_authn_requests_signed? unless want_authn_requests_signed?.nil?

        single_sign_on_services.each do |sso|
          sso.build(builder, 'SingleSignOnService')
        end

        attribute_profiles.each do |ap|
          builder['md'].AttributeProfile(ap)
        end

        attributes.each do |attr|
          attr.build(builder)
        end
      end
    end
  end
end
