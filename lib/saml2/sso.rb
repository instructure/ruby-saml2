# frozen_string_literal: true

require "saml2/role"

module SAML2
  # @abstract
  class SSO < Role
    def initialize
      super
      @single_logout_services = []
      @name_id_formats = []
    end

    # (see Base#from_xml)
    def from_xml(node)
      super
      @single_logout_services = nil
      @name_id_formats = nil
    end

    # @return [Array<Endpoint>]
    def single_logout_services
      @single_logout_services ||= load_object_array(xml, "md:SingleLogoutService", Endpoint)
    end

    # @return [Array<String>]
    def name_id_formats
      @name_id_formats ||= load_string_array(xml, "md:NameIDFormat")
    end

    protected

    # should be called from inside the role element
    def build(builder)
      super

      single_logout_services.each do |slo|
        slo.build(builder, "SingleLogoutService")
      end
      name_id_formats.each do |nif|
        builder["md"].NameIDFormat(nif)
      end
    end
  end
end
