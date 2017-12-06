require 'nokogiri'

require 'saml2/base'
require 'saml2/identity_provider'
require 'saml2/organization_and_contacts'
require 'saml2/service_provider'
require 'saml2/signable'

module SAML2
  class Entity < Base
    include OrganizationAndContacts
    include Signable

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

    class Group < Base
      include Enumerable
      include Signable

      [:each, :[]].each do |method|
        class_eval <<-RUBY, __FILE__, __LINE__ + 1
          def #{method}(*args, &block)
            @entities.#{method}(*args, &block)
          end
        RUBY
      end

      def initialize
        @entities = []
        @id = "_#{SecureRandom.uuid}"
        @valid_until = nil
      end

      def from_xml(node)
        super
        @id = nil
        remove_instance_variable(:@valid_until)
        @entities = Base.load_object_array(xml, "md:EntityDescriptor|md:EntitiesDescriptor",
                'EntityDescriptor' => Entity,
                'EntitiesDescriptor' => Group)
      end

      def valid_schema?
        Schemas.federation.valid?(xml.document)
      end

      def id
        @id ||= xml['ID']
      end

      def valid_until
        unless instance_variable_defined?(:@valid_until)
          @valid_until = xml['validUntil'] && Time.parse(xml['validUntil'])
        end
        @valid_until
      end
    end

    def initialize
      super
      @valid_until = nil
      @entity_id = nil
      @roles = []
      @id = "_#{SecureRandom.uuid}"
    end

    def from_xml(node)
      super
      @id = nil
      remove_instance_variable(:@valid_until)
      @roles = nil
    end

    def valid_schema?
      Schemas.federation.valid?(xml.document)
    end

    def entity_id
      @entity_id || xml && xml['entityID']
    end

    def id
      @id ||= xml['ID']
    end

    def valid_until
      unless instance_variable_defined?(:@valid_until)
        @valid_until = xml['validUntil'] && Time.parse(xml['validUntil'])
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
      @roles ||= load_object_array(xml, 'md:IDPSSODescriptor', IdentityProvider) +
          load_object_array(xml, 'md:SPSSODescriptor', ServiceProvider)
    end

    def build(builder)
      builder['md'].EntityDescriptor('entityID' => entity_id,
                                     'xmlns:md' => Namespaces::METADATA,
                                     'xmlns:dsig' => Namespaces::DSIG,
                                     'xmlns:xenc' => Namespaces::XENC) do |entity_descriptor|
        entity_descriptor.parent['ID'] = id if id

        roles.each do |role|
          role.build(entity_descriptor)
        end

        super
      end
    end
  end
end
