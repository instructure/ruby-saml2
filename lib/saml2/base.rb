# frozen_string_literal: true

require 'saml2/namespaces'

module SAML2
  # @abstract
  class Base
    # Create an appropriate object to represent the given XML element.
    #
    # @param node [Nokogiri::XML::Element, nil]
    # @return [Base, nil]
    def self.from_xml(node)
      return nil unless node
      result = new
      result.from_xml(node)
      result
    end

    # @return [Nokogiri::XML::Element]
    attr_reader :xml

    def initialize
      @pretty = true
    end

    # Parse an XML element into this object.
    #
    # @param node [Nokogiri::XML::Element]
    # @return [void]
    def from_xml(node)
      @xml = node
    end

    # Returns the XML of this object as a string.
    #
    # If this object came from parsing XML, it will always return it with the
    # same formatting as it was parsed.
    #
    # @param pretty optional [true, false, nil]
    #   +true+ forces it to format it for easy reading. +nil+ will prefer to
    #   format it pretty, but won't if e.g. it has been signed, and pretty
    #   formatting would break the signature.
    # @return [String]
    def to_s(pretty: nil)
      pretty = @pretty if pretty.nil?
      if xml
        xml.to_s
      elsif pretty
        to_xml.to_s
      else
        # make sure to not FORMAT it - it breaks signatures!
        to_xml.to_xml(save_with: Nokogiri::XML::Node::SaveOptions::AS_XML | Nokogiri::XML::Node::SaveOptions::NO_DECLARATION)
      end
    end

    # Inspect the object
    #
    # The +@xml+ instance variable is omitted, keeping this useful. However, if
    # an object lazily parses sub-objects, then their instance variables will
    # not be created until their attribute is accessed.
    # @return [String]
    def inspect
      "#<#{self.class.name} #{instance_variables.map { |iv| next if iv == :@xml; "#{iv}=#{instance_variable_get(iv).inspect}" }.compact.join(", ") }>"
    end

    # Serialize this object to XML
    #
    # @return [Nokogiri::XML::Document]
    def to_xml
      unless instance_variable_defined?(:@document)
        builder = Nokogiri::XML::Builder.new
        build(builder)
        @document = builder.doc
        # if we're re-serializing a parsed document (i.e. after mutating/parsing it),
        # forget the original document we parsed
        @xml = nil
      end
      @document
    end

    # Serialize this object to XML, as part of a larger document
    #
    # @param builder [Nokogiri::XML::Builder] The builder helper object to serialize to.
    # @return [void]
    def build(builder)
    end

    def self.load_string_array(node, element)
      node.xpath(element, Namespaces::ALL).map do |element_node|
        element_node.content&.strip
      end
    end


    def self.load_object_array(node, element, klass = nil)
      node.xpath(element, Namespaces::ALL).map do |element_node|
        if klass.nil?
          SAML2.const_get(element_node.name, false).from_xml(element_node)
        elsif klass.is_a?(Hash)
          klass[element_node.name].from_xml(element_node)
        else
          klass.from_xml(element_node)
        end
      end
    end

    def self.lookup_qname(qname, namespaces)
      prefix, local_name = split_qname(qname)
      [lookup_namespace(prefix, namespaces), local_name]
    end

    protected

    def load_string_array(node, element)
      self.class.load_string_array(node, element)
    end

    def load_object_array(node, element, klass = nil)
      self.class.load_object_array(node, element, klass)
    end

    def self.split_qname(qname)
      if qname.include?(':')
        qname.split(':', 2)
      else
        [nil, qname]
      end
    end

    def self.lookup_namespace(prefix, namespaces)
      return nil if namespaces.empty?
      namespaces[prefix.empty? ? 'xmlns' : "xmlns:#{prefix}"]
    end
  end
end
