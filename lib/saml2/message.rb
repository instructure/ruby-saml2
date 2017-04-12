require 'saml2/base'

module SAML2
  class InvalidMessage < RuntimeError
  end

  class MissingMessage < InvalidMessage
  end

  class CorruptMessage < InvalidMessage
  end

  class MessageTooLarge < InvalidMessage
  end

  class UnknownMessage < InvalidMessage
  end

  class UnexpectedMessage < InvalidMessage
  end

  class UnsupportedEncoding < InvalidMessage
  end

  # In the SAML Schema, Request and Response don't technically share a common
  # ancestor, but they have several things in common so it's useful to represent
  # that here
  class Message < Base
    attr_reader :id, :issue_instant
    attr_accessor :issuer, :destination

    class << self
      def inherited(klass)
        # explicitly keep track of all messages in this base class
        Message.known_messages[klass.name.sub(/^SAML2::/, '')] = klass
      end

      def from_xml(node)
        return super unless self == Message
        klass = Message.known_messages[node.name]
        raise UnknownMessage.new("Unknown message #{node.name}") unless klass
        klass.from_xml(node)
      end

      def parse(xml)
        result = Message.from_xml(Nokogiri::XML(xml) { |config| config.strict }.root)
        raise UnexpectedMessage.new("Expected a #{self.name}, but got a #{result.class.name}") unless self == Message || result.class == self
        result
      rescue Nokogiri::XML::SyntaxError
        raise CorruptMessage
      end

      protected

      def known_messages
        @known_messages ||= {}
      end
    end

    def initialize
      @id = "_#{SecureRandom.uuid}"
      @issue_instant = Time.now.utc
    end

    def from_xml(node)
      @root = node
      @id = nil
      @issue_instant = nil
      self
    end

    def valid_schema?
      return false unless Schemas.protocol.valid?(@root.document)

      true
    end

    def issuer
      @issuer ||= NameID.from_xml(@root.at_xpath('saml:Issuer', Namespaces::ALL))
    end

    def id
      @id ||= @root['ID']
    end

    protected

    # should be called from inside the specific request element
    def build(message)
      message.parent['ID'] = id
      message.parent['Version'] = '2.0'
      message.parent['IssueInstant'] = issue_instant.iso8601
      message.parent['Destination'] = destination if destination

      issuer.build(message, element: 'Issuer') if issuer
    end
  end
end
