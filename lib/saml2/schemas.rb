module SAML2
  module Schemas
    def self.metadata
      @metadata ||= Dir.chdir(File.expand_path(File.join(__FILE__, '../../../schemas'))) do
        Nokogiri::XML::Schema(File.read('saml-schema-metadata-2.0.xsd'))
      end
    end

    def self.protocol
      @protocol ||= Dir.chdir(File.expand_path(File.join(__FILE__, '../../../schemas'))) do
        Nokogiri::XML::Schema(File.read('saml-schema-protocol-2.0.xsd'))
      end
    end
  end
end
