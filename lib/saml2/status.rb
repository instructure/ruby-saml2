require 'saml2/base'

module SAML2
  class Status < Base
    SUCCESS      = "urn:oasis:names:tc:SAML:2.0:status:Success".freeze

    attr_accessor :code, :message

    def initialize(code = SUCCESS, message = nil)
      @code, @message = code, message
    end

    def from_xml(node)
      super
      self.code = node.at_xpath('samlp:StatusCode', Namespaces::ALL)['Value']
      self.message = load_string_array(xml, 'samlp:StatusMessage')
    end

    def success?
      code == SUCCESS
    end

    def build(builder)
      builder['samlp'].Status do |status|
        status['samlp'].StatusCode(Value: code)
        Array(message).each do |m|
          status['samlp'].StatusMessage(m)
        end
      end
    end
  end
end
