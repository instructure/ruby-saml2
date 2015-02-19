require 'nokogiri'

require 'saml2/assertion_consumer_service'

module SAML2
  class SPMetadata
    def self.parse(metadata)
      new(Nokogiri::XML(metadata))
    end

    def initialize(document)
      @document = document
    end

    def valid_schema?
      return false unless Schemas.metadata.validate(@document).empty?
      # Check for the correct root element
      return false unless @document.at_xpath('/md:EntityDescriptor', Namespaces::ALL)

      true
    end

    def entity_id
      @entity_id ||= @document.root['entityID']
    end

    def assertion_consumer_services
      @acs ||= begin
        nodes = @document.root.xpath('md:SPSSODescriptor/md:AssertionConsumerService', Namespaces::ALL)
        AssertionConsumerService::Array.new(nodes.map do |node|
          AssertionConsumerService.new(node['Location'],
                                       node['index'],
                                       node['isDefault'],
                                       node['Binding'])
        end)
      end
    end

    def signing_certificate
      @signing_certificate ||= begin
        node = @document.root.at_xpath("md:SPSSODescriptor/md:KeyDescriptor[@use='signing']/dsig:KeyInfo/dsig:X509Data/dsig:X509Certificate",
                                  Namespaces::ALL)
        node && node.content.strip
      end
    end
  end
end
