module SAML2
  class Attribute
    class X500 < Attribute
      GIVEN_NAME             = 'urn:oid:2.5.4.42'.freeze
      SN = SURNAME           = 'urn:oid:2.5.4.4'.freeze
      # https://www.ietf.org/rfc/rfc2798.txt
      module InetOrgPerson
        DISPLAY_NAME         = 'urn:oid:2.16.840.1.113730.3.1.241'.freeze
        EMPLOYEE_NUMBER      = 'urn:oid:2.16.840.1.113730.3.1.3'.freeze
        EMPLOYEE_TYPE        = 'urn:oid:2.16.840.1.113730.3.1.4'.freeze
        PREFERRED_LANGUAGE   = 'urn:oid:2.16.840.1.113730.3.1.39'.freeze
      end
      # https://www.internet2.edu/media/medialibrary/2013/09/04/internet2-mace-dir-eduperson-201203.html
      module EduPerson
        AFFILIATION          = 'urn:oid:1.3.6.1.4.1.5923.1.1.1.1'.freeze
        ASSURANCE            = 'urn:oid:1.3.6.1.4.1.5923.1.1.1.11'.freeze
        ENTITLEMENT          = 'urn:oid:1.3.6.1.4.1.5923.1.1.1.7'.freeze
        NICKNAME             = 'urn:oid:1.3.6.1.4.1.5923.1.1.1.2'.freeze
        ORG_D_N              = 'urn:oid:1.3.6.1.4.1.5923.1.1.1.3'.freeze
        PRIMARY_AFFILIATION  = 'urn:oid:1.3.6.1.4.1.5923.1.1.1.5'.freeze
        PRIMARY_ORG_UNIT_D_N = 'urn:oid:1.3.6.1.4.1.5923.1.1.1.8'.freeze
        PRINCIPAL_NAME       = 'urn:oid:1.3.6.1.4.1.5923.1.1.1.6'.freeze
        SCOPED_AFFILIATION   = 'urn:oid:1.3.6.1.4.1.5923.1.1.1.9'.freeze
        TARGETED_I_D         = 'urn:oid:1.3.6.1.4.1.5923.1.1.1.10'.freeze
        UNIT_D_N             = 'urn:oid:1.3.6.1.4.1.5923.1.1.1.4'.freeze
      end
      # http://www.ietf.org/rfc/rfc4519.txt
      UID = USERID           = 'urn:oid:0.9.2342.19200300.100.1.1'.freeze
      # http://www.ietf.org/rfc/rfc4524.txt
      MAIL                   = 'urn:oid:0.9.2342.19200300.100.1.3'.freeze

      def self.recognizes?(name_or_node)
        if name_or_node.is_a?(Nokogiri::XML::Element)
          !!name_or_node.at_xpath("@x500:Encoding", Namespaces::ALL)
        else
          FRIENDLY_NAMES.include?(name_or_node) || OIDS.include?(name_or_node)
        end
      end

      def initialize(name = nil, value = nil)
        # if they pass an OID, infer the friendly name
        friendly_name = OIDS[name]
        unless friendly_name
          # if they pass a friendly name, infer the OID
          proper_name = FRIENDLY_NAMES[name]
          if proper_name
            name, friendly_name = proper_name, name
          end
        end

        super(name, value, friendly_name, NameFormats::URI)
      end

      def build(builder)
        super
        attr = builder.parent.last_element_child
        attr.add_namespace_definition('x500', Namespaces::X500)
        attr['x500:Encoding'] = 'LDAP'
      end

      # build hashes out of our known attribute names for quick lookup
      FRIENDLY_NAMES = ([self] + constants).inject({}) do |hash, mod|
        mod = const_get(mod) unless mod.is_a?(Module)
        next hash unless mod.is_a?(Module)
        # Don't look in modules inherited from parent classes
        next hash unless mod.name.start_with?(self.name)
        mod.constants.each do |key|
          value = mod.const_get(key)
          next unless value.is_a?(String)
          key = key.to_s.downcase.gsub(/_\w/) { |c| c[1].upcase }
          # eduPerson prefixes all of their names
          key = "eduPerson#{key.sub(/^\w/) { |c| c.upcase }}" if mod == EduPerson
          hash[key] = value
        end
        hash
      end.freeze
      OIDS = FRIENDLY_NAMES.invert.freeze
      private_constant :FRIENDLY_NAMES, :OIDS
    end
  end
end
