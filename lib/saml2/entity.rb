# frozen_string_literal: true

require "nokogiri"

require "saml2/base"
require "saml2/identity_provider"
require "saml2/organization_and_contacts"
require "saml2/service_provider"
require "saml2/signable"

module SAML2
  class Entity < Base
    include OrganizationAndContacts
    include Signable

    # @return [String]
    attr_writer :entity_id

    # Parse a metadata file, and return an appropriate object.
    #
    # @param xml [String, IO] Anything that can be passed to +Nokogiri::XML+
    # @return [Entity, Group, nil]
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

      %i[each \[\]].each do |method|
        class_eval <<-RUBY, __FILE__, __LINE__ + 1
          def #{method}(*args, &block)          # def each(*args, &block)
            @entities.#{method}(*args, &block)  #   @entities.each(*args, &block)
          end                                   # end
        RUBY
      end

      def initialize
        super
        @entities = []
        @id = "_#{SecureRandom.uuid}"
        @valid_until = nil
      end

      # (see Base#from_xml)
      def from_xml(node)
        super
        @id = nil
        remove_instance_variable(:@valid_until)
        @entities = Base.load_object_array(xml,
                                           "md:EntityDescriptor|md:EntitiesDescriptor",
                                           "EntityDescriptor" => Entity,
                                           "EntitiesDescriptor" => Group)
      end

      # (see Message#valid_schema?)
      def valid_schema?
        Schemas.metadata.valid?(xml.document)
      end

      # (see Message#id)
      def id
        @id ||= xml["ID"]
      end

      # @return [Time, nil]
      def valid_until
        unless instance_variable_defined?(:@valid_until)
          @valid_until = xml["validUntil"] && Time.parse(xml["validUntil"])
        end
        @valid_until
      end
    end

    # @param id [String] The Entity ID
    def initialize(entity_id = nil)
      super()
      @valid_until = nil
      @entity_id = entity_id
      @roles = []
      @id = "_#{SecureRandom.uuid}"
    end

    # (see Base#from_xml)
    def from_xml(node)
      super
      @id = nil
      remove_instance_variable(:@valid_until)
      @roles = nil
    end

    # (see Message#valid_schema?)
    def valid_schema?
      Schemas.metadata.valid?(xml.document)
    end

    # @return [String]
    def entity_id
      @entity_id || (xml && xml["entityID"])
    end

    # (see Message#id)
    def id
      @id ||= xml["ID"]
    end

    # @return [Time, nil]
    def valid_until
      @valid_until = xml["validUntil"] && Time.parse(xml["validUntil"]) unless instance_variable_defined?(:@valid_until)
      @valid_until
    end

    # @return [Array<IdentityProvider>]
    def identity_providers
      roles.select { |r| r.is_a?(IdentityProvider) }
    end

    # @return [Array<ServiceProvider>]
    def service_providers
      roles.select { |r| r.is_a?(ServiceProvider) }
    end

    # @return [Array<Role>]
    def roles
      @roles ||= load_object_array(xml, "md:IDPSSODescriptor", IdentityProvider) +
                 load_object_array(xml, "md:SPSSODescriptor", ServiceProvider)
    end

    # (see Base#build)
    def build(builder)
      builder["md"].EntityDescriptor("entityID" => entity_id,
                                     "xmlns:md" => Namespaces::METADATA,
                                     "xmlns:dsig" => Namespaces::DSIG,
                                     "xmlns:xenc" => Namespaces::XENC) do |entity_descriptor|
        entity_descriptor.parent["ID"] = id if id

        roles.each do |role|
          role.build(entity_descriptor)
        end

        super
      end
    end

    # Generates an AuthnRequest
    # @param identity_provider [Entity] The metadata of the IdP to send the message to.
    def initiate_authn_request(identity_provider)
      AuthnRequest.initiate(SAML2::NameID.new(entity_id),
                            identity_provider.identity_providers.first,
                            service_provider: service_providers.first)
    end

    # Validate a message is a valid response.
    #
    # @param message [Message]
    # @param identity_provider [Entity]
    def valid_response?(message,
                        identity_provider,
                        **opts)
      unless message.is_a?(Response)
        message.errors << "not a Response object"
        return false
      end

      message.validate(service_provider: self,
                       identity_provider: identity_provider,
                       **opts).empty?
    end
  end
end
