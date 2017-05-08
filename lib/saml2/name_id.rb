require 'saml2/namespaces'

module SAML2
  class NameID
    module Format
      EMAIL_ADDRESS                 = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress".freeze
      ENTITY                        = "urn:oasis:names:tc:SAML:2.0:nameid-format:entity".freeze
      KERBEROS                      = "urn:oasis:names:tc:SAML:2.0:nameid-format:kerberos".freeze # name[/instance]@REALM
      PERSISTENT                    = "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent".freeze # opaque, pseudo-random, unique per SP-IdP pair
      TRANSIENT                     = "urn:oasis:names:tc:SAML:2.0:nameid-format:transient".freeze # opaque, will likely change
      UNSPECIFIED                   = "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified".freeze
      WINDOWS_DOMAIN_QUALIFIED_NAME = "urn:oasis:names:tc:SAML:1.1:nameid-format:WindowsDomainQualifiedName".freeze # [DomainName\]UserName
      X509_SUBJECT_NAME             = "urn:oasis:names:tc:SAML:1.1:nameid-format:X509SubjectName".freeze
    end

    class Policy < Base
      attr_writer :allow_create, :format, :sp_name_qualifier

      def initialize(allow_create = nil, format = nil, sp_name_qualifier = nil)
        @allow_create = allow_create if allow_create
        @format = format if format
        @sp_name_qualifier = sp_name_qualifier if sp_name_qualifier
      end

      def allow_create?
        if xml && !instance_variable_defined?(:@allow_create)
          @allow_create = xml['AllowCreate']&.== 'true'
        end
        @allow_create
      end

      def format
        if xml && !instance_variable_defined?(:@format)
          @format = xml['Format']
        end
        @format
      end

      def sp_name_qualifier
        if xml && !instance_variable_defined?(:@sp_name_qualifier)
          @sp_name_qualifier = xml['SPNameQualifier']
        end
        @sp_name_qualifier
      end

      def ==(rhs)
        allow_create? == rhs.allow_create? &&
            format == rhs.format &&
            sp_name_qualifier == rhs.sp_name_qualifier
      end

      def build(builder)
        builder['samlp'].NameIDPolicy do |name_id_policy|
          name_id_policy.parent['Format'] = format if format
          name_id_policy.parent['SPNameQualifier'] = sp_name_qualifier if sp_name_qualifier
          name_id_policy.parent['AllowCreate'] = allow_create? unless allow_create?.nil?
        end
      end
    end

    attr_accessor :id, :format, :name_qualifier, :sp_name_qualifier

    def self.from_xml(node)
      node && new(node.content.strip,
                  node['Format'],
                  name_qualifier: node['NameQualifier'],
                  sp_name_qualifier: node['SPNameQualifier'])
    end

    def initialize(id = nil, format = nil, name_qualifier: nil, sp_name_qualifier: nil)
      @id, @format, @name_qualifier, @sp_name_qualifier =
          id, format, name_qualifier, sp_name_qualifier
    end

    def ==(rhs)
      id == rhs.id &&
          format == rhs.format &&
          name_qualifier == rhs.name_qualifier &&
          sp_name_qualifier == rhs.sp_name_qualifier
    end

    def build(builder, element: nil)
      args = {}
      args['Format'] = format if format
      args['NameQualifier'] = name_qualifier if name_qualifier
      args['SPNameQualifier'] = sp_name_qualifier if sp_name_qualifier
      builder['saml'].__send__(element || 'NameID', id, args)
    end
  end
end
