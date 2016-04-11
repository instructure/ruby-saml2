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
        node && new.from_xml(node)
      end

      def initialize
        @valid_until = nil
      end

      def from_xml(node)
        @root = node
        remove_instance_variable(:@valid_until)
        replace(Base.load_object_array(@root, "md:EntityDescriptor|md:EntitiesDescriptor",
                'EntityDescriptor' => Entity,
                'EntitiesDescriptor' => Group))
      end

      def valid_schema?
        Schemas.metadata.valid?(@root.document)
      end

      def signed?
        !!@root.at_xpath('dsig:Signature', Namespaces::ALL)
      end

      def valid_until
        unless instance_variable_defined?(:@valid_until)
          @valid_until = @root['validUntil'] && Time.parse(@root['validUntil'])
        end
        @valid_until
      end
    end

    def initialize
      super
      @valid_until = nil
      @entity_id = nil
      @roles = []
    end

    def from_xml(node)
      @root = node
      remove_instance_variable(:@valid_until)
      @roles = nil
      super
    end

    def valid_schema?
      Schemas.metadata.valid?(@root.document)
    end

    def entity_id
      @entity_id || @root && @root['entityID']
    end

    def valid_until
      unless instance_variable_defined?(:@valid_until)
        @valid_until = @root['validUntil'] && Time.parse(@root['validUntil'])
      end
      @valid_until
    end

    def identity_providers
      roles.select { |r| r.is_a?(IdentityProvider) }
    end

    def service_providers
      roles.select { |r| r.is_a?(ServiceProvider) }
    end

    def roles
      @roles ||= load_object_array(@root, 'md:IDPSSODescriptor', IdentityProvider) +
          load_object_array(@root, 'md:SPSSODescriptor', ServiceProvider)
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
