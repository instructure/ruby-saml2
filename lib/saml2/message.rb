require 'securerandom'
require 'time'

require 'saml2/base'
require 'saml2/signable'

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

  class UnsupportedSignatureAlgorithm < InvalidMessage
  end

  class InvalidSignature < InvalidMessage
  end

  class UnsignedMessage < InvalidMessage
  end

  # In the SAML Schema, Request and Response don't technically share a common
  # ancestor, but they have several things in common so it's useful to represent
  # that here
  class Message < Base
    include Signable

    attr_writer :issuer, :destination

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
      super
      @id = "_#{SecureRandom.uuid}"
      @issue_instant = Time.now.utc
    end

    def from_xml(node)
      super
      @id = nil
      @issue_instant = nil
    end

    def valid_schema?
      return false unless Schemas.protocol.valid?(xml.document)

      true
    end

    def validate_signature(fingerprint: nil, cert: nil, verification_time: nil)
      # verify the signature (certificate's validity) as of the time the message was generated
      super(fingerprint: fingerprint, cert: cert, verification_time: issue_instant)
    end

    def sign(x509_certificate, private_key, algorithm_name = :sha256)
      super

      xml = @document.root
      # the Signature element must be right after the Issuer, so put it there
      issuer = xml.at_xpath("saml:Issuer", Namespaces::ALL)
      signature = xml.at_xpath("dsig:Signature", Namespaces::ALL)
      issuer.add_next_sibling(signature)
      self
    end

    def id
      @id ||= xml['ID']
    end

    def issue_instant
      @issue_instant ||= Time.parse(xml['IssueInstant'])
    end

    def destination
      if xml && !instance_variable_defined?(:@destination)
        @destination = xml['Destination']
      end
      @destination
    end

    def issuer
      @issuer ||= NameID.from_xml(xml.at_xpath('saml:Issuer', Namespaces::ALL))
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
