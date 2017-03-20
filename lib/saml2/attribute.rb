require 'date'

require 'active_support/core_ext/array/wrap'

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
        return super unless self == Attribute

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
      builder['saml'].Attribute('Name' => name) do |attribute|
        attribute.parent['FriendlyName'] = friendly_name if friendly_name
        attribute.parent['NameFormat'] = name_format if name_format
        Array.wrap(value).each do |value|
          xsi_type, val = convert_to_xsi(value)
          attribute['saml'].AttributeValue(val) do |attribute_value|
            attribute_value.parent['xsi:type'] = xsi_type if xsi_type
          end
        end
      end
    end

    def from_xml(node)
      @name = node['Name']
      @friendly_name = node['FriendlyName']
      @name_format = node['NameFormat']
      values = node.xpath('saml:AttributeValue', Namespaces::ALL).map do |value|
        convert_from_xsi(value.attribute_with_ns('type', Namespaces::XSI), value.content && value.content.strip)
      end
      @value = case values.length
               when 0; nil
               when 1; values.first
               else; values
               end
    end

    private
    XS_TYPES = {
      lookup_qname('xs:boolean', Namespaces::ALL) =>
        [[TrueClass, FalseClass], nil, ->(v) { %w{true 1}.include?(v) ? true : false }],
      lookup_qname('xs:string', Namespaces::ALL) =>
        [String, nil, nil],
      lookup_qname('xs:date', Namespaces::ALL) =>
        [Date, nil, ->(v) { Date.parse(v) if v }],
      lookup_qname('xs:dateTime', Namespaces::ALL) =>
        [Time, ->(v) { v.iso8601 }, ->(v) { Time.parse(v) if v }]
    }.freeze

    def convert_to_xsi(value)
      xs_type = nil
      converter = nil
      XS_TYPES.each do |type, (klasses, to_xsi, _from_xsi)|
        if Array.wrap(klasses).any? { |klass| klass === value }
          xs_type = "xs:#{type.last}"
          converter = to_xsi
          break
        end
      end
      value = converter.call(value) if converter
      [xs_type, value]
    end

    def convert_from_xsi(type, value)
      return value unless type
      qname = self.class.lookup_qname(type.value, type.namespaces)

      info = XS_TYPES[qname]
      if info && info.last
        value = info.last.call(value)
      end
      value
    end
  end

  class AttributeStatement < Base
    attr_reader :attributes

    def initialize(attributes = [])
      @attributes = attributes
    end

    def from_xml(node)
      @attributes = node.xpath('saml:Attribute', Namespaces::ALL).map do |attr|
        Attribute.from_xml(attr)
      end
    end

    def build(builder)
      builder['saml'].AttributeStatement('xmlns:xs' => Namespaces::XS,
                                         'xmlns:xsi' => Namespaces::XSI) do |statement|
        @attributes.each { |attr| attr.build(statement) }
      end
    end
  end
end

require 'saml2/attribute/x500'
