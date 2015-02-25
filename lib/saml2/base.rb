module SAML2
  class Base
    def self.from_xml(node)
      return nil unless node
      new.from_xml(node)
    end

    def from_xml(node)
      self
    end

    def to_s
      # make sure to not FORMAT it - it breaks signatures!
      to_xml.to_xml(save_with: Nokogiri::XML::Node::SaveOptions::AS_XML)
    end

    def to_xml
      unless @document
        builder = Nokogiri::XML::Builder.new
        build(builder)
        @document = builder.doc
      end
      @document
    end
  end
end
