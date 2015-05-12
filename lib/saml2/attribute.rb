require 'date'

require 'saml2/base'
require 'saml2/namespaces'

module SAML2
  class Attribute < Base
    module NameFormats
      BASIC       = "urn:oasis:names:tc:SAML:2.0:attrname-format:basic".freeze
      UNSPECIFIED = "urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified".freeze
      URI         = "urn:oasis:names:tc:SAML:2.0:attrname-format:uri".freeze
    end

    class << self
      def subclasses
        @subclasses ||= []
      end

      def inherited(klass)
        subclasses << klass
      end

      def from_xml(node)
        # pass through for subclasses
        super unless self == Attribute

        # look for an appropriate subclass
        klass = class_for(node)
        klass ? klass.from_xml(node) : super
      end

      def create(name, value = nil)

        (class_for(name) || self).new(name, value)
      end

      protected

      def class_for(name_or_node)
        subclasses.find do |klass|
          klass.respond_to?(:recognizes?) && klass.recognizes?(name_or_node)
        end
      end
    end

    attr_accessor :name, :friendly_name, :name_format, :value

    def initialize(name = nil, value = nil, friendly_name = nil, name_format = nil)
      @name, @value, @friendly_name, @name_format = name, value, friendly_name, name_format
    end

    def build(builder)
      builder['saml'].Attribute('Name' => name) do |builder|
        builder.parent['FriendlyName'] = friendly_name if friendly_name
        builder.parent['NameFormat'] = name_format if name_format
        Array(value).each do |val|
          xsi_type, val = convert_to_xsi(value)
          builder['saml'].AttributeValue(val) do |builder|
            builder.parent['xsi:type'] = xsi_type if xsi_type
          end
        end
      end
    end

    def from_xml(node)
      @name = node['Name']
      @friendly_name = node['FriendlyName']
      @name_format = node['NameFormat']
      values = node.xpath('saml:AttributeValue', Namespaces::ALL).map do |node|
        convert_from_xsi(node['xsi:type'], node.content && node.content.strip)
      end
      @value = case values.length
               when 0; nil
               when 1; values.first
               else; values
               end
      super
    end

    private
    XSI_TYPES = {
        'xsd:string' => [String, nil, nil],
        nil => [DateTime, ->(v) { v.iso8601 }, ->(v) { DateTime.parse(v) if v }]
    }.freeze

    def convert_to_xsi(value)
      xsi_type = nil
      converter = nil
      XSI_TYPES.each do |type, (klass, to_xsi, from_xsi)|
        if klass === value
          xsi_type = type
          converter = to_xsi
          break
        end
      end
      value = converter.call(value) if converter
      [xsi_type, value]
    end

    def convert_from_xsi(type, value)
      info = XSI_TYPES[type]
      if info && info.last
        value = info.last.call(value)
      end
      value
    end
  end

  class AttributeStatement
    attr_reader :attributes

    def initialize(attributes)
      @attributes = attributes
    end

    def build(builder)
      builder['saml'].AttributeStatement('xmlns:xsi' => Namespaces::XSI) do |builder|
        @attributes.each { |attr| attr.build(builder) }
      end
    end
  end
end

require 'saml2/attribute/x500'
