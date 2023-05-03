# frozen_string_literal: true

require "saml2/namespaces"

module SAML2
  # @abstract
  class Base
    class << self
      def lookup_qname(qname, namespaces)
        prefix, local_name = split_qname(qname)
        [lookup_namespace(prefix, namespaces), local_name]
      end

      # Create an appropriate object to represent the given XML element.
      #
      # @param node [Nokogiri::XML::Element, nil]
      # @return [Base, nil]
      def from_xml(node)
        return nil unless node

        result = new
        result.from_xml(node)
        result
      end

      def load_string_array(node, element)
        node.xpath(element, Namespaces::ALL).map do |element_node|
          element_node.content&.strip
        end
      end

      def load_object_array(node, element, klass = nil)
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

      private

      def split_qname(qname)
        if qname.include?(":")
          qname.split(":", 2)
        else
          [nil, qname]
        end
      end

      def lookup_namespace(prefix, namespaces)
        return nil if namespaces.empty?

        namespaces[prefix.empty? ? "xmlns" : "xmlns:#{prefix}"]
      end
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
    # @param pretty optional [true, false, nil]
    #   +true+ forces it to format it for easy reading. +nil+ will prefer to
    #   format it pretty, but won't if e.g. it has been signed, and pretty
    #   formatting would break the signature. If this object came from parsing
    #   XML, it will default to exactly what it was parsed as.
    # @return [String]
    def to_s(pretty: nil)
      pretty = @pretty if pretty.nil?
      if xml
        if pretty
          xml.to_s
        else
          xml.to_xml(save_with: Nokogiri::XML::Node::SaveOptions::AS_XML |
                                Nokogiri::XML::Node::SaveOptions::NO_DECLARATION)
        end
      elsif pretty
        to_xml.to_s
      else
        # make sure to not FORMAT it - it breaks signatures!
        to_xml.to_xml(save_with: Nokogiri::XML::Node::SaveOptions::AS_XML |
                                 Nokogiri::XML::Node::SaveOptions::NO_DECLARATION)
      end
    end

    # Inspect the object
    #
    # The +@xml+ instance variable is omitted, keeping this useful. However, if
    # an object lazily parses sub-objects, then their instance variables will
    # not be created until their attribute is accessed.
    # @return [String]
    def inspect
      "#<#{self.class.name} #{instance_variables.filter_map do |iv|
                                next if iv == :@xml

                                "#{iv}=#{instance_variable_get(iv).inspect}"
                              end.join(", ")}>"
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
    def build(builder); end

    # Decrypt (in-place) encrypted portions of this object
    #
    # Either the +keys+ parameter, or a block that returns key(s), should be
    # provided.
    #
    # @param keys optional [Array<OpenSSL::PKey, String>, OpenSSL::PKey, String, nil]
    # @yield Optional block to fetch the necessary keys, given information
    #   contained in the encrypted elements of which certificates it was
    #   encrypted for.
    # @yieldparam allowed_certs [Array<OpenSSL::X509::Certificate, Hash, String, nil>]
    #   An array of certificates describing who the node was encrypted for.
    #   Identified by an X.509 Certificate, a hash with +:issuer+ and +:serial+
    #   keys, or a string of SubjectName.
    # @yieldreturn [Array<OpenSSL::PKey, String>, OpenSSL::PKey, String, nil]
    # @return [Boolean] If any nodes were present.
    def decrypt(keys = nil)
      encrypted_nodes = self.encrypted_nodes
      encrypted_nodes.each do |node|
        this_nodes_keys = keys
        if keys.nil?
          allowed_certs = node.xpath("dsig:KeyInfo/xenc:EncryptedKey/dsig:KeyInfo/dsig:X509Data",
                                     SAML2::Namespaces::ALL).map do |x509data|
            if (cert = x509data.at_xpath("dsig:X509Certificate", SAML2::Namespaces::ALL)&.content&.strip)
              OpenSSL::X509::Certificate.new(Base64.decode64(cert))
            elsif (issuer_serial = x509data.at_xpath("dsig:X509IssuerSerial", SAML2::Namespaces::ALL))
              {
                issuer: issuer_serial.at_xpath("dsig:X509IssuerName", SAML2::Namespaces::ALL).content.strip,
                serial: issuer_serial.at_xpath("dsig:X509SerialNumber", SAML2::Namespaces::ALL).content.strip.to_i
              }
            elsif (subject_name = x509data.at_xpath("dsig:X509SubjectName", SAML2::Namespaces::ALL)&.content&.strip)
              subject_name
            end
          end
          this_nodes_keys = yield allowed_certs
        end
        this_nodes_keys = Array(this_nodes_keys)
        raise ArgumentError("no decryption key provided or found") if this_nodes_keys.empty?

        old_node = node.parent
        this_nodes_keys.each_with_index do |key, i|
          old_node.replace(node.decrypt_with(key: key))
        rescue XMLSec::DecryptionError
          # swallow errors on all but the last key
          raise if i - 1 == this_nodes_keys.length
        end
      end
      !encrypted_nodes.empty?
    end

    private

    def load_string_array(node, element)
      self.class.load_string_array(node, element)
    end

    def load_object_array(node, element, klass = nil)
      self.class.load_object_array(node, element, klass)
    end

    def encrypted_nodes
      xml.xpath("//xenc:EncryptedData", Namespaces::ALL)
    end
  end
end
