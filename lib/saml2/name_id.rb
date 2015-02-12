module SAML2
  class NameID
    module Format
      PERSISTENT = "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent".freeze
      UNSPECIFIED = "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified".freeze
    end

    class Policy
      attr_reader :format

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

    def initialize(id = nil, format = nil)
      @id, @format = id, format
    end

    def ==(rhs)
      id == rhs.id && format == rhs.format
    end
  end
end
