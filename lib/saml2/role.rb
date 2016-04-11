require 'set'

require 'saml2/base'
require 'saml2/organization_and_contacts'
require 'saml2/key'

module SAML2
  class Role < Base
    module Protocols
      SAML2 = 'urn:oasis:names:tc:SAML:2.0:protocol'.freeze
    end

    include OrganizationAndContacts

    attr_writer :supported_protocols, :keys

    def initialize
      super
      @supported_protocols = Set.new
      @supported_protocols << Protocols::SAML2
      @keys = []
    end

    def from_xml(node)
      super
      @root = node
      @supported_protocols = nil
      @keys = nil
    end

    def supported_protocols
      @supported_protocols ||= @root['protocolSupportEnumeration'].split
    end

    def keys
      @keys ||= load_object_array(@root, 'md:KeyDescriptor', Key)
    end

    def signing_keys
      keys.select { |key| key.signing? }
    end

    def encryption_keys
      keys.select { |key| key.encryption? }
    end

    protected
    # should be called from inside the role element
    def build(builder)
      builder.parent['protocolSupportEnumeration'] = supported_protocols.to_a.join(' ')
      keys.each do |key|
        key.build(builder)
      end
      super
    end
  end
end
