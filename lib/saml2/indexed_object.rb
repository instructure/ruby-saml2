require 'saml2/base'

module SAML2
  module IndexedObject
    attr_reader :index

    def eql?(rhs)
      index == rhs.index &&
          default? == rhs.default? &&
          super
    end

    def default?
      @is_default
    end

    def from_xml(node)
      @index = node['index'] && node['index'].to_i
      @is_default = node['isDefault'] && node['isDefault'] == 'true'
      super
    end

    class Array < ::Array
      attr_reader :default

      def self.from_xml(nodes)
        new(nodes.map { |node| name.split('::')[1..-2].inject(SAML2) { |mod, klass| mod.const_get(klass) }.from_xml(node) })
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

    def build(builder)
      super
      builder.parent.last['index'] = index
      builder.parent.last['isDefault'] = default? unless default?.nil?
    end

    private
    def self.included(klass)
      klass.const_set(:Array, Array.dup)
    end
  end
end
