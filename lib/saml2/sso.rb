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
      @single_logout_services ||= @root.xpath('md:SingleLogoutService', Namespaces::ALL).map do |node|
        Endpoint.from_xml(node)
      end
    end

    def name_id_formats
      @name_id_formats ||= @root.xpath('md:NameIDFormat', Namespaces::ALL).map do |node|
        node.content && node.content.strip
      end
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
