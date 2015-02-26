require 'saml2/name_id'
require 'saml2/namespaces'

module SAML2
  class Subject
    attr_accessor :name_id

    def self.from_xml(node)
      return nil unless node
      subject = new
      subject.name_id = NameID.from_xml(node.at_xpath('saml:NameID', Namespaces::ALL))

      subject
    end

    def build(builder)
      builder['saml'].Subject do |builder|
        name_id.build(builder)
      end
    end
  end
end
