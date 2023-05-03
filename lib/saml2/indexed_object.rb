# frozen_string_literal: true

require "saml2/base"

module SAML2
  module IndexedObject
    # @return [Integer]
    attr_accessor :index

    def initialize(*)
      @is_default = nil
      super
    end

    def eql?(other)
      index == other.index &&
        default? == other.default? &&
        super
    end

    def default?
      !!@is_default
    end

    def default_defined?
      !@is_default.nil?
    end

    # (see Base#from_xml)
    def from_xml(node)
      @index = node["index"]&.to_i
      @is_default = node["isDefault"] && node["isDefault"] == "true"
      super
    end

    # Keeps an Array of {IndexedObject}s in their +index+ed order.
    class Array < ::Array
      # Returns the first object which is set as the default, or the first
      # object if none are set as the default.
      # @return [IndexedObject]
      attr_reader :default

      def self.from_xml(nodes)
        new(nodes.map do |node|
              name.split("::")[1..-2].inject(SAML2) do |mod, klass|
                mod.const_get(klass)
              end.from_xml(node)
            end).freeze
      end

      def initialize(objects = nil)
        super()
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
        last_index = -1
        @index = {}
        each do |object|
          object.index ||= last_index + 1
          last_index = object.index
          @index[object.index] = object
        end
        @default = find(&:default?) || first
      end
    end

    # (see Base#build)
    def build(builder, *)
      super
      builder.parent.children.last["index"] = index
      builder.parent.children.last["isDefault"] = default? if default_defined?
    end

    def self.included(klass)
      klass.const_set(:Array, Array.dup)
    end
  end
end
