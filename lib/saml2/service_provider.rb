require 'nokogiri'

require 'saml2/assertion_consumer_service'
require 'saml2/organization'

module SAML2
  class ServiceProvider
    attr_reader :entity

    def initialize(entity, root)
      @entity, @root = entity, root
    end

    def assertion_consumer_services
      @assertion_consumer_services ||= begin
        nodes = @root.xpath('md:AssertionConsumerService', Namespaces::ALL)
        AssertionConsumerService::Array.from_xml(nodes)
      end
    end

    def attribute_consuming_services
      @attribute_consuming_services ||= begin
        nodes = @root.xpath('md:AttributeConsumingService', Namespaces::ALL)
        AttributeConsumingService::Array.from_xml(nodes)
      end
    end

    def signing_certificate
      @signing_certificate ||= begin
        node = @root.at_xpath("md:KeyDescriptor[@use='signing']/dsig:KeyInfo/dsig:X509Data/dsig:X509Certificate",
                                  Namespaces::ALL)
        node && node.content.strip
      end
    end
  end
end
