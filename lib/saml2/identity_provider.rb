require 'saml2/attribute'
require 'saml2/namespaces'
require 'saml2/sso'

module SAML2
  class IdentityProvider < SSO
    attr_writer :want_authn_requests_signed, :single_sign_on_services, :attribute_profiles, :attributes

    def initialize(node = nil)
      super(node)
      unless node
        @want_authn_requests_signed = nil
        @single_sign_on_services = []
        @attribute_profiles = []
        @attributes = []
      end
    end

    def want_authn_requests_signed?
      unless instance_variable_defined?(:@want_authn_requests_signed)
        @want_authn_requests_signed = @root['WantAuthnRequestsSigned'] && @root['WantAuthnRequestsSigned'] == 'true'
      end
      @want_authn_requests_signed
    end

    def single_sign_on_services
      @single_sign_on_services ||= @root.xpath('md:SingleSignOnService', Namespaces::ALL).map do |node|
        Endpoint.from_xml(node)
      end
    end

    def attribute_profiles
      @attribute_profiles ||= @root.xpath('md:AttributeProfile', Namespaces::ALL).map do |node|
        node.content && node.content.strip
      end
    end

    def attributes
      @attributes ||= @root.xpath('saml:Attribute', Namespaces::ALL).map do |node|
        Attribute.from_xml(node)
      end
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
