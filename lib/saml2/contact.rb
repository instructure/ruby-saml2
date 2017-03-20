require 'saml2/base'

module SAML2
  class Contact
    module Type
      ADMINISTRATIVE = 'administrative'.freeze
      BILLING        = 'billing'.freeze
      OTHER          = 'other'.freeze
      SUPPORT        = 'support'.freeze
      TECHNICAL      = 'technical'.freeze
    end

    attr_accessor :type, :company, :given_name, :surname, :email_addresses, :telephone_numbers

    def self.from_xml(node)
      return nil unless node

      result = new(node['contactType'])
      company = node.at_xpath('md:Company', Namespaces::ALL)
      result.company = company && company.content && company.content.strip
      given_name = node.at_xpath('md:GivenName', Namespaces::ALL)
      result.given_name = given_name && given_name.content && given_name.content.strip
      surname = node.at_xpath('md:SurName', Namespaces::ALL)
      result.surname = surname && surname.content && surname.content.strip
      result.email_addresses = Base.load_string_array(node, 'md:EmailAddress')
      result.telephone_numbers = Base.load_string_array(node, 'md:TelephoneNumber')
      result
    end

    def initialize(type = Type::OTHER)
      @type = type
      @email_addresses = []
      @telephone_numbers = []
    end

    def build(builder)
      builder['md'].ContactPerson('contactType' => type) do |contact_person|
        contact_person['md'].Company(company) if company
        contact_person['md'].GivenName(given_name) if given_name
        contact_person['md'].SurName(surname) if surname
        email_addresses.each do |email|
          contact_person['md'].EmailAddress(email)
        end
        telephone_numbers.each do |tel|
          contact_person['md'].TelephoneNumber(tel)
        end
      end
    end
  end
end
