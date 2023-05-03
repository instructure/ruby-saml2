# frozen_string_literal: true

require "date"

require "active_support/core_ext/array/wrap"

require "saml2/base"
require "saml2/namespaces"

module SAML2
  class Attribute < Base
    module NameFormats
      BASIC       = "urn:oasis:names:tc:SAML:2.0:attrname-format:basic"
      UNSPECIFIED = "urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified"
      URI         = "urn:oasis:names:tc:SAML:2.0:attrname-format:uri"
    end

    class << self
      # (see Base.from_xml)
      def from_xml(node)
        # pass through for subclasses
        return super unless self == Attribute

        # look for an appropriate subclass
        klass = class_for(node)
        klass ? klass.from_xml(node) : super
      end

      # Create an appropriate object to represent an attribute.
      #
      # This will create the most appropriate object (i.e. an
      # {Attribute::X500} if possible) to represent this attribute,
      # based on its name.
      # @param name [String]
      #   The attribute name. This can be a friendly name, or a URI.
      # @param value optional
      #   The attribute value.
      # @return [Attribute]
      def create(name, value = nil)
        (class_for(name) || self).new(name, value)
      end

      # The XML namespace that this attribute class serializes as.
      # @return ['saml']
      def namespace
        "saml"
      end

      # The XML element that this attribute class serializes as.
      # @return ['Attribute']
      def element
        "Attribute"
      end

      protected

      def subclasses
        @subclasses ||= []
      end

      def inherited(klass)
        super
        subclasses << klass
      end

      def class_for(name_or_node)
        subclasses.find do |klass|
          klass.respond_to?(:recognizes?) && klass.recognizes?(name_or_node)
        end
      end
    end

    # @return [String]
    attr_accessor :name
    # @return [String, nil]
    attr_accessor :friendly_name, :name_format
    # @return [Object, nil]
    attr_accessor :value

    # Create a new generic Attribute
    #
    # @param name [String]
    # @param value optional [Object, nil]
    # @param friendly_name optional [String, nil]
    # @param name_format optional [String, nil]
    def initialize(name = nil, value = nil, friendly_name = nil, name_format = nil)
      super()
      @name = name
      @value = value
      @friendly_name = friendly_name
      @name_format = name_format
    end

    # (see Base#build)
    def build(builder)
      builder[self.class.namespace].__send__(self.class.element, "Name" => name) do |attribute|
        attribute.parent["FriendlyName"] = friendly_name if friendly_name
        attribute.parent["NameFormat"] = name_format if name_format
        Array.wrap(value).each do |value|
          xsi_type, val = convert_to_xsi(value)
          attribute["saml"].AttributeValue(val) do |attribute_value|
            attribute_value.parent["xsi:type"] = xsi_type if xsi_type
          end
        end
      end
    end

    # (see Base#from_xml)
    def from_xml(node)
      super
      @name = node["Name"]
      @friendly_name = node["FriendlyName"]
      @name_format = node["NameFormat"]
      values = node.xpath("saml:AttributeValue", Namespaces::ALL).map do |value|
        convert_from_xsi(value.attribute_with_ns("type", Namespaces::XSI), value.content && value.content.strip)
      end
      @value = case values.length
               when 0 then nil
               when 1 then values.first
               else; values
               end
    end

    private

    XS_TYPES = {
      lookup_qname("xs:boolean", Namespaces::ALL) =>
        [[TrueClass, FalseClass], nil, ->(v) { %w[true 1].include?(v) }],
      lookup_qname("xs:string", Namespaces::ALL) =>
        [String, nil, nil],
      lookup_qname("xs:date", Namespaces::ALL) =>
        [Date, nil, ->(v) { Date.parse(v) if v }],
      lookup_qname("xs:dateTime", Namespaces::ALL) =>
        [Time, ->(v) { v.iso8601 }, ->(v) { Time.parse(v) if v }]
    }.freeze

    def convert_to_xsi(value)
      xs_type = nil
      converter = nil
      XS_TYPES.each do |type, (klasses, to_xsi, _from_xsi)|
        next unless Array.wrap(klasses).any? { |klass| value.is_a?(klass) }

        xs_type = "xs:#{type.last}"
        converter = to_xsi
        break
      end
      value = converter.call(value) if converter
      [xs_type, value]
    end

    def convert_from_xsi(type, value)
      return value unless type

      qname = self.class.lookup_qname(type.value, type.namespaces)

      info = XS_TYPES[qname]
      value = info.last.call(value) if info&.last
      value
    end
  end

  class AttributeStatement < Base
    attr_reader :attributes

    def initialize(attributes = [])
      super()
      @attributes = attributes
    end

    def from_xml(node)
      super
      @attributes = node.xpath("saml:Attribute", Namespaces::ALL).map do |attr|
        Attribute.from_xml(attr)
      end
    end

    # Convert the {AttributeStatement} to a {Hash}
    #
    # Repeated attributes become an array.
    #
    # @param name optional [:name, :friendly_name, :both]
    #   Which name field to use as keys to the hash. If :both
    #   is specified, attributes may be duplicated under both
    #   names.
    def to_h(name = :both)
      return to_h(:friendly_name).merge(to_h(:name)) if name == :both

      result = {}
      attributes.each do |attribute|
        key = attribute.send(name)
        # fall back to name on missing friendly name;
        # no need for the opposite, because name is required
        key ||= attribute.name if name == :friendly_name

        prior_value = result[key]
        result[key] = if prior_value
                        value = Array.wrap(prior_value)
                        # repeated key; convert to array
                        if attribute.value.is_a?(Array)
                          # both values are arrays; concatenate them
                          value.concat(attribute.value)
                        else
                          value << attribute.value
                        end
                        value
                      else
                        attribute.value
                      end
      end
      result
    end

    def build(builder)
      builder["saml"].AttributeStatement("xmlns:xs" => Namespaces::XS,
                                         "xmlns:xsi" => Namespaces::XSI) do |statement|
        @attributes.each { |attr| attr.build(statement) }
      end
    end
  end
end

require "saml2/attribute/x500"
