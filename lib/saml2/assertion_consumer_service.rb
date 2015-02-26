require 'saml2/indexed_object'

module SAML2
  class AssertionConsumerService < IndexedObject
    module Bindings
      HTTP_POST = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST".freeze
    end

    attr_reader :location, :binding

    def initialize(location = nil, index = nil, is_default = false, binding = Bindings::HTTP_POST)
      super(index, is_default)
      @location, @binding = location, binding
    end

    def from_xml(node)
      @location = node['Location']
      @binding = node['Binding']
      super
    end

    def ==(rhs)
      location == rhs.location && binding == rhs.binding
    end

    def eql?(rhs)
      location == rhs.location &&
          binding == rhs.binding && super
    end
  end
end
