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

    class Group < Base
      include Enumerable
      [:each, :[]].each do |method|
        class_eval <<-RUBY, __FILE__, __LINE__ + 1
          def #{method}(*args, &block)
            @entities.#{method}(*args, &block)
          end
        RUBY
      end

      def initialize
        @entities = []
        @valid_until = nil
      end

      def from_xml(node)
        super
        remove_instance_variable(:@valid_until)
        @entities = Base.load_object_array(xml, "md:EntityDescriptor|md:EntitiesDescriptor",
                'EntityDescriptor' => Entity,
                'EntitiesDescriptor' => Group)
      end

      def valid_schema?
        Schemas.federation.valid?(xml.document)
      end

      def signature
        unless instance_variable_defined?(:@signature)
          @signature = xml.at_xpath('dsig:Signature', Namespaces::ALL)
          signed_node = @signature.at_xpath('dsig:SignedInfo/dsig:Reference', Namespaces::ALL)['URI']
          # validating the schema will automatically add ID attributes, so check that first
          xml.set_id_attribute('ID') unless xml.document.get_id(xml['ID'])
          @signature = nil unless signed_node == "##{xml['ID']}"
        end
        @signature
      end

      def signed?
        !!signature
      end

      def valid_signature?(*args)
        signature.verify_with(*args)
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
    end

    def from_xml(node)
      super
      remove_instance_variable(:@valid_until)
      @roles = nil
    end

    def valid_schema?
      Schemas.federation.valid?(xml.document)
    end

    def entity_id
      @entity_id || xml && xml['entityID']
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
        roles.each do |role|
          role.build(entity_descriptor)
        end

        super
      end
    end
  end
end
