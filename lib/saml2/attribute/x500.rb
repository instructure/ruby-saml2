# frozen_string_literal: true

module SAML2
  class Attribute
    class X500 < Attribute
      GIVEN_NAME             = "urn:oid:2.5.4.42"
      SN = SURNAME           = "urn:oid:2.5.4.4"
      # https://www.ietf.org/rfc/rfc2798.txt
      module InetOrgPerson
        DISPLAY_NAME         = "urn:oid:2.16.840.1.113730.3.1.241"
        EMPLOYEE_NUMBER      = "urn:oid:2.16.840.1.113730.3.1.3"
        EMPLOYEE_TYPE        = "urn:oid:2.16.840.1.113730.3.1.4"
        PREFERRED_LANGUAGE   = "urn:oid:2.16.840.1.113730.3.1.39"
      end

      # https://www.internet2.edu/media/medialibrary/2013/09/04/internet2-mace-dir-eduperson-201203.html
      module EduPerson
        AFFILIATION          = "urn:oid:1.3.6.1.4.1.5923.1.1.1.1"
        ASSURANCE            = "urn:oid:1.3.6.1.4.1.5923.1.1.1.11"
        ENTITLEMENT          = "urn:oid:1.3.6.1.4.1.5923.1.1.1.7"
        NICKNAME             = "urn:oid:1.3.6.1.4.1.5923.1.1.1.2"
        ORG_D_N              = "urn:oid:1.3.6.1.4.1.5923.1.1.1.3"
        ORG_UNIT_D_N         = "urn:oid:1.3.6.1.4.1.5923.1.1.1.4"
        PRIMARY_AFFILIATION  = "urn:oid:1.3.6.1.4.1.5923.1.1.1.5"
        PRIMARY_ORG_UNIT_D_N = "urn:oid:1.3.6.1.4.1.5923.1.1.1.8"
        PRINCIPAL_NAME       = "urn:oid:1.3.6.1.4.1.5923.1.1.1.6"
        SCOPED_AFFILIATION   = "urn:oid:1.3.6.1.4.1.5923.1.1.1.9"
        TARGETED_I_D         = "urn:oid:1.3.6.1.4.1.5923.1.1.1.10"
      end
      # http://www.ietf.org/rfc/rfc4519.txt
      UID = USERID           = "urn:oid:0.9.2342.19200300.100.1.1"
      # http://www.ietf.org/rfc/rfc4524.txt
      MAIL                   = "urn:oid:0.9.2342.19200300.100.1.3"

      # Returns true if the param should be an {X500} Attribute.
      # @param name_or_node [String, Nokogiri::XML::Element]
      def self.recognizes?(name_or_node)
        if name_or_node.is_a?(Nokogiri::XML::Element)
          !!name_or_node.at_xpath("@x500:Encoding", Namespaces::ALL) ||
            ((name_or_node["NameFormat"] == NameFormats::URI || name_or_node["NameFormat"].nil?) &&
              OIDS.include?(name_or_node["Name"]))
        else
          FRIENDLY_NAMES.include?(name_or_node) || OIDS.include?(name_or_node)
        end
      end

      # Create a new X.500 attribute.
      #
      # The name format will always be set to URI.
      #
      # @param name [String]
      #   Either an OID or a known friendly name. The opposite value will be
      #   inferred automatically.
      # @param value optional [Object, nil]
      def initialize(name = nil, value = nil)
        # if they pass an OID, infer the friendly name
        friendly_name = OIDS[name]
        unless friendly_name
          # if they pass a friendly name, infer the OID
          proper_name = FRIENDLY_NAMES[name]
          if proper_name
            friendly_name = name
            name = proper_name
          end
        end

        super(name, value, friendly_name, NameFormats::URI)
      end

      # (see Base.from_xml)
      def from_xml(node)
        super
        # infer the friendly name if not provided
        self.friendly_name ||= OIDS[name]
        self
      end

      # (see Base#build)
      def build(builder)
        super
        attr = builder.parent.last_element_child
        attr.add_namespace_definition("x500", Namespaces::X500)
        attr["x500:Encoding"] = "LDAP"
      end

      # build hashes out of our known attribute names for quick lookup
      FRIENDLY_NAMES = ([self] + constants).each_with_object({}) do |mod, hash|
        mod = const_get(mod) unless mod.is_a?(Module)
        next hash unless mod.is_a?(Module)
        # Don't look in modules inherited from parent classes
        next hash unless mod.name.start_with?(name)

        mod.constants.each do |key|
          value = mod.const_get(key)
          next unless value.is_a?(String)

          key = key.to_s.downcase.gsub(/_\w/) { |c| c[1].upcase }
          # eduPerson prefixes all of their names
          key = "eduPerson#{key.sub(/^\w/, &:upcase)}" if mod == EduPerson
          hash[key] = value
        end
      end.freeze
      OIDS = FRIENDLY_NAMES.invert.freeze
      private_constant :FRIENDLY_NAMES, :OIDS
    end
  end
end
