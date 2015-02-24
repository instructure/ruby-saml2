require 'saml2/namespaces'

module SAML2
  class Key
    module Type
      ENCRYPTION = 'encryption'.freeze
      SIGNING    = 'signing'.freeze
    end

    attr_accessor :use, :x509, :encryption_methods

    def self.from_xml(node)
      return nil unless node

      x509 = node.at_xpath('dsig:KeyInfo/dsig:X509Data/dsig:X509Certificate', Namespaces::ALL)
      methods = node.xpath('xenc:EncryptionMethod', Namespaces::ALL)
      new(x509 && x509.content.strip, node['use'], methods.map { |m| m['Algorithm'] })
    end

    def initialize(x509, use = nil, encryption_methods = [])
      @use, @x509, @encryption_methods = use, x509, encryption_methods
    end

    def encryption?
      use.nil? || use == Type::ENCRYPTION
    end

    def signing?
      use.nil? || use == Type::SIGNING
    end

    def build(builder)
      builder['md'].KeyDescriptor do |builder|
        builder.parent['use'] = use if use
        builder['dsig'].KeyInfo do |builder|
          builder['dsig'].X509Data do |builder|
            builder['dsig'].X509Certificate(x509)
          end
        end
        encryption_methods.each do |method|
          builder['xenc'].EncryptionMethod('Algorithm' => method)
        end
      end
    end
  end
end
