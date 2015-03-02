require 'saml2/role'

module SAML2
  class SSO < Role
    attr_reader :single_logout_services, :name_id_formats

    def initialize(node = nil)
      super
      unless node
        @single_logout_services = []
        @name_id_formats = []
      end
    end

    def single_logout_services
      @single_logout_services ||= load_object_array(@root, 'md:SingleLogoutService', Endpoint)
    end

    def name_id_formats
      @name_id_formats ||= load_string_array(@root, 'md:NameIDFormat')
    end

    protected
    # should be called from inside the role element
    def build(builder)
      super

      single_logout_services.each do |slo|
        slo.build(builder, 'SingleLogoutService')
      end
      name_id_formats.each do |nif|
        builder['md'].NameIDFormat(nif)
      end
    end
  end
end
