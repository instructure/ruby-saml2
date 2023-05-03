# frozen_string_literal: true

require "saml2/base"
require "saml2/namespaces"

module SAML2
  class LocalizedName < Hash
    attr_reader :element

    def initialize(element, name = nil)
      super()
      @element = element
      return if name.nil?

      if name.is_a?(Hash)
        replace(name)
      else
        self[nil] = name
      end
    end

    # @param lang [String, Symbol, :all, nil]
    #   The language to retrieve the localized string for.
    #   +:all+ will return the hash itself, and +nil+ will return the first
    #   localized string regardless of language.
    # @return [String]
    def [](lang)
      case lang
      when :all
        self
      when nil
        !empty? && first.last
      else
        super(lang.to_sym)
      end
    end

    # @return [String] The first localized string regardless of language
    def to_s
      self[nil].to_s
    end

    def from_xml(nodes)
      clear
      nodes.each do |node|
        self[node["xml:lang"].to_sym] = node.content && node.content.strip
      end
      self
    end

    def build(builder)
      each do |lang, value|
        builder["md"].__send__(element, value, "xml:lang" => lang)
      end
    end
  end
end
