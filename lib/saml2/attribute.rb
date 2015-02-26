require 'saml2/base'

module SAML2
  class AttributeType < Base
    attr_accessor :name, :name_format

    def initialize(name = nil, name_format = nil)
      @name, @name_format = name, name_format
    end

    def from_xml(node)
      @name = node['Name']
      @name_format = node['NameFormat']
      self
    end
  end

  class Attribute < AttributeType
    module NameFormats
      BASIC       = "urn:oasis:names:tc:SAML:2.0:attrname-format:basic".freeze
      UNSPECIFIED = "urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified".freeze
      URI         = "urn:oasis:names:tc:SAML:2.0:attrname-format:uri".freeze
    end

    attr_accessor :value

    def initialize(name, value = nil, name_format = nil)
      super(name, name_format)
      @value = value
    end

    def build(builder)
      builder['saml'].Attribute('Name' => name) do |builder|
        builder.parent['NameFormat'] = name_format if name_format
        Array(value).each do |val|
          val = val.iso8601 if val.respond_to?(:iso8601)
          builder['saml'].AttributeValue(val.to_s)
        end
      end
    end
  end

  class AttributeStatement
    attr_reader :attributes

    def initialize(attributes)
      @attributes = attributes
    end

    def build(builder)
      builder['saml'].AttributeStatement do |builder|
        @attributes.each { |attr| attr.build(builder) }
      end
    end
  end
end
