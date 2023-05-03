# frozen_string_literal: true

require "saml2/message"
require "saml2/status"

module SAML2
  class StatusResponse < Message
    # @return [String]
    attr_accessor :in_response_to
    attr_writer :status

    def initialize
      super
      @status = Status.new
    end

    # (see Base#from_xml)
    def from_xml(node)
      super
      @status = nil
      remove_instance_variable(:@status)
      @in_response_to = node["InResponseTo"]
    end

    # @return [Status]
    def status
      @status ||= Status.from_xml(xml.at_xpath("samlp:Status", Namespaces::ALL))
    end

    protected

    def build(status_response)
      super(status_response)

      status_response.parent["InResponseTo"] = in_response_to if in_response_to

      status.build(status_response)
    end
  end
end
