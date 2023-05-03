# frozen_string_literal: true

module SAML2
  module Schemas
    class << self
      def metadata
        @metadata ||= schema("metadata_combined.xsd")
      end

      def protocol
        @protocol ||= schema("saml-schema-protocol-2.0.xsd")
      end

      private

      def schema(filename)
        Dir.chdir(File.expand_path(File.join(__FILE__, "../../../schemas"))) do
          Nokogiri::XML::Schema(File.read(filename))
        end
      end
    end
  end
end
