# frozen_string_literal: true

require "saml2/base"

module SAML2
  class Contact < Base
    module Type
      ADMINISTRATIVE = "administrative"
      BILLING        = "billing"
      OTHER          = "other"
      SUPPORT        = "support"
      TECHNICAL      = "technical"
    end

    # @see Type
    # @return [String]
    attr_accessor :type
    # @return [String, nil]
    attr_accessor :company, :given_name, :surname
    # @return [Array<String>]
    attr_accessor :email_addresses, :telephone_numbers

    # @param type [String]
    def initialize(type = Type::OTHER)
      super()
      @type = type
      @email_addresses = []
      @telephone_numbers = []
    end

    # (see Base#from_xml)
    def from_xml(node)
      self.type = node["contactType"]
      company = node.at_xpath("md:Company", Namespaces::ALL)
      self.company = company && company.content && company.content.strip
      given_name = node.at_xpath("md:GivenName", Namespaces::ALL)
      self.given_name = given_name && given_name.content && given_name.content.strip
      surname = node.at_xpath("md:SurName", Namespaces::ALL)
      self.surname = surname && surname.content && surname.content.strip
      self.email_addresses = load_string_array(node, "md:EmailAddress")
      self.telephone_numbers = load_string_array(node, "md:TelephoneNumber")
      self
    end

    # (see Base#build)
    def build(builder)
      builder["md"].ContactPerson("contactType" => type) do |contact_person|
        contact_person["md"].Company(company) if company
        contact_person["md"].GivenName(given_name) if given_name
        contact_person["md"].SurName(surname) if surname
        email_addresses.each do |email|
          contact_person["md"].EmailAddress(email)
        end
        telephone_numbers.each do |tel|
          contact_person["md"].TelephoneNumber(tel)
        end
      end
    end
  end
end
