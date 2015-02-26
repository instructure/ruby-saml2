require 'saml2/attribute'
require 'saml2/indexed_object'
require 'saml2/namespaces'

module SAML2
  class RequestedAttribute < AttributeType
    def initialize(name = nil, is_required = nil, name_format = nil)
      super(name, name_format)
      @is_required = is_required
    end

    def from_xml(node)
      @is_required = node['isRequired'] && node['isRequired'] == 'true'
      super
    end

    def required?
      @is_required
    end
  end

  class RequiredAttributeMissing < RuntimeError
    attr_reader :requested_attribute

    def initialize(requested_attribute)
      super("Required attribute #{requested_attribute.name} not provided")
      @requested_attribute = requested_attribute
    end
  end

  class AttributeConsumingService < IndexedObject
    attr_reader :name, :requested_attributes

    def initialize(name = nil, requested_attributes = [])
      @name, @requested_attributes = name, requested_attributes
    end

    def from_xml(node)
      nodes = node.xpath("md:RequestedAttribute", Namespaces::ALL)
      @name = node['ServiceName']
      @requested_attributes = nodes.map { |attr| RequestedAttribute.from_xml(attr) }
      super
    end

    def create_statement(attributes)
      if attributes.is_a?(Hash)
        attributes = attributes.map { |k, v| Attribute.new(k, v) }
      end

      attributes_hash = {}
      attributes.each do |attr|
        attr.value = attr.value.call if attr.value.respond_to?(:call)
        attributes_hash[[attr.name, attr.name_format]] = attr
        if attr.name_format
          attributes_hash[[attr.name, nil]] = attr
        end
      end

      attributes = []
      requested_attributes.each do |requested_attr|
        attr = attributes_hash[[requested_attr.name, requested_attr.name_format]]
        if requested_attr.name_format
          attr ||= attributes_hash[[requested_attr.name, nil]]
        end
        if attr
          attributes << attr
        elsif requested_attr.required?
          raise RequiredAttributeMissing.new(requested_attr)
        end
      end
      AttributeStatement.new(attributes)
    end
  end
end
