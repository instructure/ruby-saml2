# frozen_string_literal: true

require 'set'

require 'saml2/base'
require 'saml2/key'
require 'saml2/organization_and_contacts'
require 'saml2/signable'

module SAML2
  # @abstract
  class Role < Base
    module Protocols
      SAML2 = 'urn:oasis:names:tc:SAML:2.0:protocol'
    end

    include OrganizationAndContacts
    include Signable

    attr_writer :supported_protocols, :keys

    def initialize
      super
      @supported_protocols = Set.new
      @supported_protocols << Protocols::SAML2
      @keys = []
    end

    # (see Base#from_xml)
    def from_xml(node)
      super
      @supported_protocols = nil
      @keys = nil
    end

    # @see Protocols
    # @return [Array<String>]
    def supported_protocols
      @supported_protocols ||= xml['protocolSupportEnumeration'].split
    end

    # @return [Array<KeyDescriptor>]
    def keys
      @keys ||= load_object_array(xml, 'md:KeyDescriptor', KeyDescriptor)
    end

    # @return [Array<KeyDescriptor>]
    def signing_keys
      keys.select { |key| key.signing? }
    end

    # @return [Array<KeyDescriptor>]
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
