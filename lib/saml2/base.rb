module SAML2
  class Base
    def to_s
      # make sure to not FORMAT it - it breaks signatures!
      to_xml.to_xml(save_with: Nokogiri::XML::Node::SaveOptions::AS_XML)
    end

    def document
      @document ||= Nokogiri::XML::Document.new
    end
  end
end
