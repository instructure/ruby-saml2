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

    class Policy
      attr_reader :format

      def self.from_xml(node)
        if node
          allow_create = node['AllowCreate'].nil? ? nil : node['AllowCreate'] == 'true'
          NameID::Policy.new(allow_create, node['Format'])
        end
      end

      def initialize(allow_create, format)
        @allow_create, @format = allow_create, format
      end

      def allow_create?
        @allow_create
      end

      def ==(rhs)
        format == rhs.format && allow_create? == rhs.allow_create?
      end
    end

    attr_reader :id, :format

    def self.from_xml(node)
      node && new(node.content.strip, node['Format'])
    end

    def initialize(id = nil, format = nil)
      @id, @format = id, format
    end

    def ==(rhs)
      id == rhs.id && format == rhs.format
    end

    def build(builder, options = {})
      args = {}
      args['Format'] = format if format
      args['xmlns:saml'] = Namespaces::SAML if options[:include_namespace]
      builder['saml'].__send__(options.delete(:element) || 'NameID', id, args)
    end
  end
end
