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
      result.company = company && company.strip
      given_name = node.at_xpath('md:GivenName', Namespaces::ALL)
      result.given_name = given_name && given_name.strip
      surname = node.at_xpath('md:SurName', Namespaces::ALL)
      result.surname = surname && surname.strip
      result.email_addresses = node.xpath('md:EmailAddress', Namespaces::ALL).map { |node| node.content && node.content.strip }
      result.telephone_numbers = node.xpath('md:TelephoneNumber', Namespaces::ALL).map { |node| node.content && node.content.strip }
      result
    end

    def initialize(type = Type::OTHER)
      @type = type
      @email_addresses = []
      @telephone_numbers = []
    end

    def build(builder)
      builder['md'].ContactPerson('contactType' => type) do |builder|
        builder['md'].Company(company) if company
        builder['md'].GivenName(given_name) if given_name
        builder['md'].SurName(surname) if surname
        email_addresses.each do |email|
          builder['md'].EmailAddress(email)
        end
        telephone_numbers.each do |tel|
          builder['md'].TelephoneNumber(tel)
        end
      end
    end
  end
end
