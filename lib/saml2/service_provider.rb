require 'nokogiri'

require 'saml2/endpoint'
require 'saml2/sso'

module SAML2
  class ServiceProvider < SSO
    def initialize
      super
      @assertion_consumer_services = []
      @attribute_consuming_services = []
    end

    def from_xml(node)
      super
      @assertion_consumer_services = nil
      @attribute_consuming_services = nil
    end

    def assertion_consumer_services
      @assertion_consumer_services ||= begin
        nodes = @root.xpath('md:AssertionConsumerService', Namespaces::ALL)
        Endpoint::Indexed::Array.from_xml(nodes)
      end
    end

    def attribute_consuming_services
      @attribute_consuming_services ||= begin
        nodes = @root.xpath('md:AttributeConsumingService', Namespaces::ALL)
        AttributeConsumingService::Array.from_xml(nodes)
      end
    end

    def build(builder)
      builder['md'].SPSSODescriptor do |sp_sso_descriptor|
        super(sp_sso_descriptor)

        assertion_consumer_services.each do |acs|
          acs.build(sp_sso_descriptor, 'AssertionConsumerService')
        end
      end
    end
  end
end
