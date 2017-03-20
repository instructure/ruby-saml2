require 'saml2/namespaces'

module SAML2
  class Organization
    def self.from_xml(node)
      return nil unless node

      new(nodes_to_hash(node.xpath('md:OrganizationName', Namespaces::ALL)),
        nodes_to_hash(node.xpath('md:OrganizationDisplayName', Namespaces::ALL)),
        nodes_to_hash(node.xpath('md:OrganizationURL', Namespaces::ALL)))
    end

    def initialize(name, display_name, url)
      if !name.is_a?(Hash)
        name = { nil => name}
      end
      if !display_name.is_a?(Hash)
        display_name = { nil => display_name }
      end
      if !url.is_a?(Hash)
        url = { nil => url }
      end

      @name, @display_name, @url = name, display_name, url
    end

    def name(lang = nil)
      self.class.localized_name(@name, lang)
    end

    def display_name(lang = nil)
      self.class.localized_name(@display_name, lang)
    end

    def url(lang = nil)
      self.class.localized_name(@url, lang)
    end

    def build(builder)
      builder['md'].Organization do |organization|
        self.class.build(organization, @name, 'OrganizationName')
        self.class.build(organization, @display_name, 'OrganizationDisplayName')
        self.class.build(organization, @url, 'OrganizationURL')
      end
    end

    private

    def self.build(builder, hash, element)
      hash.each do |lang, value|
        builder['md'].__send__(element, value, 'xml:lang' => lang)
      end
    end

    def self.nodes_to_hash(nodes)
      hash = {}
      nodes.each do |node|
        hash[node['xml:lang'].to_sym] = node.content && node.content.strip
      end
      hash
    end

    def self.localized_name(hash, lang)
      case lang
        when :all
          hash
        when nil
          !hash.empty? && hash.first.last
        else
          hash[lang.to_sym]
      end
    end
  end
end
