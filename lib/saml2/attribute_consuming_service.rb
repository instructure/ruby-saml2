# frozen_string_literal: true

require "active_support/core_ext/array/wrap"

require "saml2/attribute"
require "saml2/indexed_object"
require "saml2/localized_name"
require "saml2/namespaces"

module SAML2
  class RequestedAttribute < Attribute
    class << self
      # The XML namespace that this attribute class serializes as.
      # @return ['md']
      def namespace
        "md"
      end

      # The XML element that this attribute class serializes as.
      # @return ['RequestedAttribute']
      def element
        "RequestedAttribute"
      end

      # Create a RequestAttribute object to represent an attribute.
      #
      # {Attribute.create} will be used to create a temporary object, so that
      # attribute-class specific inferences (i.e. {Attribute::X500} friendly
      # names) will be done, but always returns a {RequestedAttribute}.
      # @param name [String]
      #   The attribute name. This can be a friendly name, or a URI.
      # @param is_required optional [true, false, nil]
      # @return [RequestedAttribute]
      def create(name, is_required = nil)
        attribute = Attribute.create(name)
        new(attribute.name, is_required, attribute.friendly_name, attribute.name_format)
      end
    end

    # Create a new {RequestedAttribute}.
    #
    # @param name [String]
    # @param is_required optional [true, false, nil]
    # @param friendly_name optional [String, nil]
    # @param name_format optional [String, nil]
    def initialize(name = nil, is_required = nil, friendly_name = nil, name_format = nil)
      super(name, nil, friendly_name, name_format)
      @is_required = is_required
    end

    # (see Base#from_xml)
    def from_xml(node)
      super
      @is_required = node["isRequired"] && node["isRequired"] == "true"
    end

    # @return [true, false, nil]
    def required?
      @is_required
    end
  end

  class RequiredAttributeMissing < RuntimeError
    # @return [RequestedAttribute]
    attr_reader :requested_attribute

    # @param requested_attribute [RequestedAttribute]
    def initialize(requested_attribute)
      super("Required attribute #{requested_attribute.name} not provided")
      @requested_attribute = requested_attribute
    end
  end

  class InvalidAttributeValue < RuntimeError
    # @return [RequestedAttribute]
    attr_reader :requested_attribute
    attr_reader :provided_value

    # @param requested_attribute [RequestedAttribute]
    def initialize(requested_attribute, provided_value)
      super("Attribute #{requested_attribute.name} is provided value " \
            "#{provided_value.inspect}, but only allows " \
            "#{Array.wrap(requested_attribute.value).inspect}")
      @requested_attribute = requested_attribute
      @provided_value = provided_value
    end
  end

  class AttributeConsumingService < Base
    include IndexedObject

    # @return [LocalizedName]
    attr_reader :name, :description
    # @return [Array<RequestedAttribute>]
    attr_reader :requested_attributes

    # @param name [String]
    # @param requested_attributes [::Array<RequestedAttributes>]
    def initialize(name = nil, requested_attributes = [])
      super()
      @name = LocalizedName.new("ServiceName", name)
      @description = LocalizedName.new("ServiceDescription")
      @requested_attributes = requested_attributes
    end

    # (see Base#from_xml)
    def from_xml(node)
      super
      name.from_xml(node.xpath("md:ServiceName", Namespaces::ALL))
      description.from_xml(node.xpath("md:ServiceDescription", Namespaces::ALL))
      @requested_attributes = load_object_array(node, "md:RequestedAttribute", RequestedAttribute)
    end

    # Create an {AttributeStatement} from the given attributes hash.
    #
    # Given a set of attributes, create and return an {AttributeStatement}
    # with only the attributes that this {AttributeConsumingService} requests.
    #
    # @param attributes [Hash<String => Object>, Array<Attribute>]
    #   If it's a hash, the elements are run through {Attribute.create} first
    #   in order to create proper {Attribute} objects.
    # @return [AttributeStatement]
    # @raise [InvalidAttributeValue]
    #   If a {RequestedAttribute} specifies that only specific values are
    #   permissible, and the provided attribute does not match that value.
    # @raise [RequiredAttributeMissing]
    #   If a {RequestedAttribute} is tagged as required, but it has not been
    #   supplied.
    def create_statement(attributes)
      attributes = attributes.map { |k, v| Attribute.create(k, v) } if attributes.is_a?(Hash)

      attributes_hash = {}
      attributes.each do |attr|
        attr.value = attr.value.call if attr.value.respond_to?(:call)
        attributes_hash[[attr.name, attr.name_format]] = attr
        attributes_hash[[attr.name, nil]] = attr if attr.name_format
      end

      attributes = []
      requested_attributes.each do |requested_attr|
        attr = attributes_hash[[requested_attr.name, requested_attr.name_format]]
        attr ||= attributes_hash[[requested_attr.name, nil]] if requested_attr.name_format
        if attr
          if requested_attr.value &&
             !Array.wrap(requested_attr.value).include?(attr.value)
            raise InvalidAttributeValue.new(requested_attr, attr.value)
          end

          attributes << attr
        elsif requested_attr.required?
          # if the metadata includes only one possible value, helpfully set
          # that value
          unless requested_attr.value && !requested_attr.value.is_a?(::Array)
            raise RequiredAttributeMissing, requested_attr
          end

          attributes << Attribute.create(requested_attr.name,
                                         requested_attr.value)

        end
      end
      return nil if attributes.empty?

      AttributeStatement.new(attributes)
    end

    # (see Base#build)
    def build(builder)
      builder["md"].AttributeConsumingService do |attribute_consuming_service|
        name.build(attribute_consuming_service)
        description.build(attribute_consuming_service)
        requested_attributes.each do |requested_attribute|
          requested_attribute.build(attribute_consuming_service)
        end
      end
      super
    end
  end
end
