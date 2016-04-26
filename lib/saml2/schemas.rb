module SAML2
  module Schemas
    def self.federation
      @federation ||= schema('ws-federation.xsd')
    end

    def self.metadata
      @metadata ||= schema('saml-schema-metadata-2.0.xsd')
    end

    def self.protocol
      @protocol ||= schema('saml-schema-protocol-2.0.xsd')
    end

    private
    def self.schema(filename)
      Dir.chdir(File.expand_path(File.join(__FILE__, '../../../schemas'))) do
        Nokogiri::XML::Schema(File.read(filename))
      end
    end
  end
end
