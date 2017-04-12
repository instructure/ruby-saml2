require 'saml2/message'

module SAML2
  class StatusResponse < Message
    module Status
      SUCCESS = "urn:oasis:names:tc:SAML:2.0:status:Success".freeze
    end

    attr_accessor :in_response_to, :status_code

    def initialize
      super
      @status_code = Status::SUCCESS
    end

    protected

    def build(status_response)
      super(status_response)

      status_response.parent['InResponseTo'] = in_response_to if in_response_to

      status_response['samlp'].Status do |status|
        status['samlp'].StatusCode(Value: status_code)
      end
    end
  end
end
