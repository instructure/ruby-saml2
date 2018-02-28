# frozen_string_literal: true

require 'saml2/base'
require 'saml2/namespaces'

module SAML2
  class NameID < Base
    module Format
      EMAIL_ADDRESS                 = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
      ENTITY                        = "urn:oasis:names:tc:SAML:2.0:nameid-format:entity"
      KERBEROS                      = "urn:oasis:names:tc:SAML:2.0:nameid-format:kerberos" # name[/instance]@REALM
      PERSISTENT                    = "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent" # opaque, pseudo-random, unique per SP-IdP pair
      TRANSIENT                     = "urn:oasis:names:tc:SAML:2.0:nameid-format:transient" # opaque, will likely change
      UNSPECIFIED                   = "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified"
      WINDOWS_DOMAIN_QUALIFIED_NAME = "urn:oasis:names:tc:SAML:1.1:nameid-format:WindowsDomainQualifiedName" # [DomainName\]UserName
      X509_SUBJECT_NAME             = "urn:oasis:names:tc:SAML:1.1:nameid-format:X509SubjectName"
    end

    class Policy < Base
      # @return [Boolean, nil]
      attr_writer :allow_create
      attr_writer :format, :sp_name_qualifier

      # @param allow_create optional [Boolean]
      # @param format optional [String]
      # @param sp_name_qualifier optional [String]
      def initialize(allow_create = nil, format = nil, sp_name_qualifier = nil)
        @allow_create = allow_create if allow_create
        @format = format if format
        @sp_name_qualifier = sp_name_qualifier if sp_name_qualifier
      end

      # @return [Boolean, nil]
      def allow_create?
        if xml && !instance_variable_defined?(:@allow_create)
          @allow_create = xml['AllowCreate']&.== 'true'
        end
        @allow_create
      end

      # @see Format
      # @return [String, nil]
      def format
        if xml && !instance_variable_defined?(:@format)
          @format = xml['Format']
        end
        @format
      end

      # @return [String, nil]
      def sp_name_qualifier
        if xml && !instance_variable_defined?(:@sp_name_qualifier)
          @sp_name_qualifier = xml['SPNameQualifier']
        end
        @sp_name_qualifier
      end

      # @param rhs [Policy]
      # @return [Boolean]
      def ==(rhs)
        allow_create? == rhs.allow_create? &&
            format == rhs.format &&
            sp_name_qualifier == rhs.sp_name_qualifier
      end

      # (see Base#build)
      def build(builder)
        builder['samlp'].NameIDPolicy do |name_id_policy|
          name_id_policy.parent['Format'] = format if format
          name_id_policy.parent['SPNameQualifier'] = sp_name_qualifier if sp_name_qualifier
          name_id_policy.parent['AllowCreate'] = allow_create? unless allow_create?.nil?
        end
      end
    end

    # @return [String]
    attr_accessor :id
    # @return [String, nil]
    attr_accessor :format, :name_qualifier, :sp_name_qualifier

    # (see Base#from_xml)
    def from_xml(node)
      self.id = node.content.strip
      self.format = node['Format']
      self.name_qualifier = node['NameQualifier']
      self.sp_name_qualifier = node['SPNameQualifier']
    end

    # @param id [String]
    # @param format optional [String]
    # @param name_qualifier optional [String]
    # @param sp_name_qualifier optional [String]
    def initialize(id = nil, format = nil, name_qualifier: nil, sp_name_qualifier: nil)
      @id, @format, @name_qualifier, @sp_name_qualifier =
          id, format, name_qualifier, sp_name_qualifier
    end

    # @param rhs [NameID]
    # @return [Boolean]
    def ==(rhs)
      id == rhs.id &&
          format == rhs.format &&
          name_qualifier == rhs.name_qualifier &&
          sp_name_qualifier == rhs.sp_name_qualifier
    end

    # (see Base#build)
    def build(builder, element: nil)
      args = {}
      args['Format'] = format if format
      args['NameQualifier'] = name_qualifier if name_qualifier
      args['SPNameQualifier'] = sp_name_qualifier if sp_name_qualifier
      builder['saml'].__send__(element || 'NameID', id, args)
    end
  end
end
