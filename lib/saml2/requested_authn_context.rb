require 'saml2/base'

module SAML2
  class RequestedAuthnContext < Base
    attr_accessor :comparison, :class_ref

    def build(builder)
      builder['samlp'].RequestedAuthnContext do |requested_authn_context|
        requested_authn_context.parent['Comparison'] = comparison.to_s if comparison
        Array(class_ref).each do |individual_class_ref|
          requested_authn_context['saml'].AuthnContextClassRef(individual_class_ref)
        end
      end
    end
  end
end
