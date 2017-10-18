require 'saml2/base'

module SAML2
  module IndexedObject
    attr_reader :index

    def initialize(*args)
      @is_default = nil
      super
    end

    def eql?(rhs)
      index == rhs.index &&
          default? == rhs.default? &&
          super
    end

    def default?
      !!@is_default
    end

    def default_defined?
      !@is_default.nil?
    end

    def from_xml(node)
      @index = node['index'] && node['index'].to_i
      @is_default = node['isDefault'] && node['isDefault'] == 'true'
      super
    end

    class Array < ::Array
      attr_reader :default

      def self.from_xml(nodes)
        new(nodes.map { |node| name.split('::')[1..-2].inject(SAML2) { |mod, klass| mod.const_get(klass) }.from_xml(node) }).freeze
      end

      def initialize(objects = nil)
        replace(objects.sort_by { |object| object.index || 0 }) if objects
        re_index
      end

      def [](index)
        @index[index]
      end

      def resolve(index)
        index ? self[index] : default
      end

      def <<(value)
        super
        re_index
      end

      protected

      def re_index
        @index = {}
        each { |object| @index[object.index] = object }
        @default = find { |object| object.default? } || first
      end
    end

    def build(builder, *)
      super
      builder.parent.children.last['index'] = index
      builder.parent.children.last['isDefault'] = default? if default_defined?
    end

    private
    def self.included(klass)
      klass.const_set(:Array, Array.dup)
    end
  end
end
