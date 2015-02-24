require 'nokogiri'

require 'saml2/base'
require 'saml2/identity_provider'
require 'saml2/organization_and_contacts'
require 'saml2/service_provider'

module SAML2
  class Entity < Base
    include OrganizationAndContacts

    attr_writer :entity_id

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

    def initialize(root = nil)
      super
      @root = root
      unless @root
        @roles = []
      end
    end

    def valid_schema?
      Schemas.metadata.valid?(@root.document)
    end

    def entity_id
      @entity_id || @root && @root['entityID']
    end

    def roles
      @roles ||= @root.xpath('md:SPSSODescriptor', Namespaces::ALL).map do |node|
        case node.name
        when 'SPSSODescriptor'
          ServiceProvider.new(self, node)
        end
      end
    end

    def build(builder)
      builder['md'].EntityDescriptor('entityID' => entity_id,
                                     'xmlns:md' => Namespaces::METADATA,
                                     'xmlns:dsig' => Namespaces::DSIG,
                                     'xmlns:xenc' => Namespaces::XENC) do |builder|
        roles.each do |role|
          role.build(builder)
        end

        super
      end
    end
  end
end
