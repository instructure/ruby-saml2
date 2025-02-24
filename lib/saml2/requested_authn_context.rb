# frozen_string_literal: true

require "saml2/base"

module SAML2
  class RequestedAuthnContext < Base
    # @return [String, nil]
    attr_accessor :comparison
    # @return [String, Array<String>]
    attr_accessor :class_ref

    def initialize(class_ref = nil)
      super()
      @class_ref = class_ref
    end

    # (see Base#from_xml)
    def from_xml(node)
      super
      @class_ref = load_string_array(node, "saml:AuthnContextClassRef")
    end

    # (see Base#build)
    def build(builder)
      builder["samlp"].RequestedAuthnContext do |requested_authn_context|
        requested_authn_context.parent["Comparison"] = comparison.to_s if comparison
        Array(class_ref).each do |individual_class_ref|
          requested_authn_context["saml"].AuthnContextClassRef(individual_class_ref)
        end
      end
    end
  end
end
