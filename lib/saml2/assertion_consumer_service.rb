module SAML2
  class AssertionConsumerService
    module Bindings
      HTTP_POST = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST".freeze
    end

    attr_reader :location, :index, :binding

    def initialize(location, index, is_default = false, binding = Bindings::HTTP_POST)
      @location, @index, @is_default, @binding = location, index && index.to_i, is_default, binding
    end

    def ==(rhs)
      location == rhs.location && binding == rhs.binding
    end

    def eql?(rhs)
      location == rhs.location &&
          binding == rhs.binding &&
          index == rhs.index &&
          is_default? == rhs.is_default?
    end

    def is_default?
      @is_default
    end

    class Array < ::Array
      attr_reader :default

      def initialize(acses)
        replace(acses.sort_by { |acs| acs.index || 0 })
        @index = {}
        each { |acs| @index[acs.index] = acs }
        @default = find { |acs| acs.is_default? } || first

        freeze
      end

      def [](index)
        @index[index]
      end
    end
  end
end
