require 'saml2/base'

module SAML2
  class IndexedObject < Base
    attr_reader :index

    def initialize(index = nil, is_default = false)
      @index, @is_default = index, is_default
    end

    def eql?(rhs)
      index == rhs.index &&
          is_default? == rhs.is_default?
    end

    def default?
      @is_default
    end

    def from_xml(node)
      @index = node['index'] && node['index'].to_i
      @is_default = node['isDefault'] && node['isDefault'] == 'true'
      self
    end

    class Array < ::Array
      attr_reader :default

      def self.from_xml(nodes)
        new(nodes.map { |node| SAML2.const_get(name.split('::')[-2]).from_xml(node) })
      end

      def initialize(objects)
        replace(objects.sort_by { |object| object.index || 0 })
        @index = {}
        each { |object| @index[object.index] = object }
        @default = find { |object| object.default? } || first

        freeze
      end

      def [](index)
        @index[index]
      end

      def resolve(index)
        index ? self[index] : default
      end
    end

    private
    def self.inherited(subclass)
      subclass.const_set(:Array, Array.dup)
    end
  end
end