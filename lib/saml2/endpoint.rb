# frozen_string_literal: true

require "saml2/bindings/http_post"

module SAML2
  class Endpoint < Base
    module ChoiceHelpers
      # Choose a binding supported by this list of endpoints
      #
      # @return [String]
      def choose_binding(*bindings)
        (bindings & map(&:binding)).first
      end

      # Choose an endpoint from this list of endpoints that supports a given binding
      #
      # @param binding [String] the binding that must match
      # @return [Endpoint, nil]
      def choose_endpoint(binding)
        find { |endpoint| endpoint.binding == binding }
      end
    end

    class Array < ::Array
      include ChoiceHelpers

      def self.from_xml(nodes)
        new(nodes.map do |node|
              Endpoint.from_xml(node)
            end).freeze
      end
    end

    class Indexed < Endpoint
      include IndexedObject

      class Array
        include ChoiceHelpers

        # Choose a binding supported by this list of endpoints
        #
        # Note that if there is a default endpoint, its binding will be preferred even
        # over the order of the bindings passed in (as long as it is included in the list
        # at all).
        # @return [String]
        def choose_binding(*bindings)
          return default.binding if default && bindings.include?(default.binding)

          super
        end

        # Choose an endpoint from this list of endpoints that supports a given binding
        #
        # Note that if there is a default endpoint, it will be returned if its binding matches
        # even over earlier endpoints in the list.
        # @param binding [String] the binding that must match
        # @return [Endpoint, nil]
        def choose_endpoint(binding)
          return default if default && default.binding == binding

          super
        end
      end

      # @param location [String]
      # @param index [Integer]
      # @param is_default [true, false, nil]
      # @param binding [String]
      # @param response_location [String, nil]
      def initialize(location = nil,
                     index = nil,
                     is_default = nil,
                     binding = Bindings::HTTP_POST::URN,
                     response_location = nil)
        super(location, binding, response_location)
        @index = index
        @is_default = is_default
      end

      def eql?(other)
        location == other.location &&
          binding == other.binding &&
          response_location == other.response_location &&
          super
      end

      # @return [String]
      def inspect
        "#<SAML2::Endpoint::Indexed #{endpoint_inspect} #{indexed_object_inspect}>"
      end
    end

    # @return [String]
    attr_accessor :location, :binding
    # @return [String, nil]
    attr_accessor :response_location

    # @param location [String]
    # @param binding [String]
    # @param response_location [String, nil]
    def initialize(location = nil, binding = Bindings::HTTP_POST::URN, response_location = nil)
      super()
      @location = location
      @binding = binding
      @response_location = response_location
    end

    # @param rhs [Endpoint]
    # @return [Boolean]
    def ==(other)
      other.is_a?(Endpoint) &&
        location == other.location && binding == other.binding && response_location == other.response_location
    end

    # (see Base#from_xml)
    def from_xml(node)
      super
      @location = node["Location"]
      @binding = node["Binding"]
      @response_location = node["ResponseLocation"]
    end

    # (see Base#build)
    def build(builder, element)
      builder["md"].__send__(element, "Location" => location, "Binding" => binding) do |b|
        b.ResponseLocation = response_location if response_location
      end
    end

    # @!attribute[r]
    # @return [String]
    # The {response_location} if there is one, otherwise the {location}
    def effective_response_location
      response_location || location
    end

    # @return [String]
    def inspect
      "#<SAML2::Endpoint #{endpoint_inspect}>"
    end

    private

    def endpoint_inspect
      r = "location=#{location.inspect}"
      r += " binding=#{binding.inspect}" if binding
      r += " response_location=#{response_location.inspect}" if response_location
      r
    end
  end
end
