# frozen_string_literal: true

require "saml2/bindings/http_post"

module SAML2
  class Endpoint < Base
    # @return [String]
    attr_reader :location, :binding

    # @param location [String]
    # @param binding [String]
    def initialize(location = nil, binding = Bindings::HTTP_POST::URN)
      super()
      @location = location
      @binding = binding
    end

    # @param rhs [Endpoint]
    # @return [Boolean]
    def ==(other)
      location == other.location && binding == other.binding
    end

    # (see Base#from_xml)
    def from_xml(node)
      super
      @location = node["Location"]
      @binding = node["Binding"]
    end

    # (see Base#build)
    def build(builder, element)
      builder["md"].__send__(element, "Location" => location, "Binding" => binding)
    end

    class Indexed < Endpoint
      include IndexedObject

      # @param location [String]
      # @param index [Integer]
      # @param is_default [true, false, nil]
      # @param binding [String]
      def initialize(location = nil, index = nil, is_default = nil, binding = Bindings::HTTP_POST::URN)
        super(location, binding)
        @index = index
        @is_default = is_default
      end

      def eql?(other)
        location == other.location &&
          binding == other.binding && super
      end
    end
  end
end
