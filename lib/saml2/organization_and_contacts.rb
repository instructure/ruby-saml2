# frozen_string_literal: true

require "saml2/contact"
require "saml2/organization"

module SAML2
  module OrganizationAndContacts
    attr_writer :organization, :contacts

    def initialize
      @organization = nil
      @contacts = []
    end

    # (see Base#from_xml)
    def from_xml(node)
      remove_instance_variable(:@organization)
      @contacts = nil
      super
    end

    # @return [Organization, nil]
    def organization
      unless instance_variable_defined?(:@organization)
        @organization = Organization.from_xml(xml.at_xpath("md:Organization", Namespaces::ALL))
      end
      @organization
    end

    # @return [Array<Contact>]
    def contacts
      @contacts ||= load_object_array(xml, "md:ContactPerson", Contact)
    end

    protected

    def build(builder)
      organization&.build(builder)
      contacts.each do |contact|
        contact.build(builder)
      end
    end
  end
end
