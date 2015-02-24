require 'nokogiri'
require 'saml2/service_provider'

module SAML2
  class Entity
    def self.parse(xml)
      document = Nokogiri::XML(xml)

      # Root can be an array (EntitiesDescriptor), or a single Entity (EntityDescriptor)
      entities = document.at_xpath("/md:EntitiesDescriptor", Namespaces::ALL)
      entity = document.at_xpath("/md:EntityDescriptor", Namespaces::ALL)
      if entities
        Group.from_xml(entities)
      elsif entity
        from_xml(entity)
      else
        nil
      end
    end

    class Group < Array
      def self.from_xml(node)
        node && new(node)
      end

      def initialize(root)
        @root = root
        replace(root.xpath("md:EntityDescriptor|md:EntitiesDescriptor", Namespaces::ALL).map do |node|
                  case name
                  when 'EntityDescriptor'
                    Entity.from_xml(node)
                  when 'EntitiesDescriptor'
                    Group.from_xml(node)
                  end
                end
        )
      end

      def valid_schema?
        Schemas.metadata.valid?(@root.document)
      end
    end

    def self.from_xml(node)
      node && new(node)
    end

    def initialize(root)
      @root = root
    end

    def valid_schema?
      Schemas.metadata.valid?(@root.document)
    end

    def entity_id
      @root['entityID']
    end

    def organization
      @organization ||= Organization.from_xml(@root.at_xpath('md:Organization', Namespaces::ALL))
    end

    def roles
      @roles ||= @root.xpath('md:SPSSODescriptor', Namespaces::ALL).map do |node|
        case node.name
        when 'SPSSODescriptor'
          ServiceProvider.new(self, node)
        end
      end
    end
  end
end
