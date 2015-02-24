module SAML2
  class Endpoint < Base
    module Bindings
      HTTP_POST     = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST".freeze
      HTTP_REDIRECT = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect".freeze
    end

    module Encodings
      DEFLATE= "urn:oasis:names:tc:SAML:2.0:bindings:URL-Encoding:DEFLATE".freeze
    end

    attr_reader :location, :binding

    def initialize(location, binding = Bindings::HTTP_POST)
      @location, @binding = location, binding
    end

    def ==(rhs)
      location == rhs.location && binding == rhs.binding
    end

    def from_xml(node)
      @location = node['Location']
      @binding = node['Binding']
      self
    end

    def build(builder, element)
      builder['md'].__send__(element, 'Location' => location, 'Binding' => binding)
    end

    class Indexed < Endpoint
      include IndexedObject

      def initialize(location = nil, index = nil, is_default = false, binding = Bindings::HTTP_POST)
        super(location, binding)
        @index, @is_default = index, is_default
      end

      def eql?(rhs)
        location == rhs.location &&
            binding == rhs.binding && super
      end
    end
  end
end
