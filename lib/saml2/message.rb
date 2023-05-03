# frozen_string_literal: true

require "securerandom"
require "time"

require "saml2/base"
require "saml2/signable"

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
  # that in this gem as a common base class.
  # @abstract
  class Message < Base
    include Signable

    attr_reader :errors
    attr_writer :issuer, :destination

    class << self
      # Create an appropriate {Message} subclass instance to represent the
      # given XML element.
      #
      # When called on a subclass, it behaves the same as {Base.from_xml}
      #
      # @param node [Nokogiri::XML::Element]
      # @return [Message]
      # @raise [UnknownMessage] If the element doesn't correspond to a known
      #   SAML message type.
      def from_xml(node)
        return super unless self == Message

        klass = Message.known_messages[node.name]
        raise UnknownMessage, "Unknown message #{node.name}" unless klass

        klass.from_xml(node)
      end

      # Parses XML, and returns an appropriate {Message} subclass instance.
      #
      # @param xml [String, IO] Anything that can be passed to +Nokogiri::XML+.
      # @return [Message]
      # @raise [UnexpectedMessage]
      #   If called on a subclass, will raise if the parsed message does not
      #   match the class is was called on.
      def parse(xml)
        result = Message.from_xml(Nokogiri::XML(xml, &:strict).root)
        unless self == Message || result.instance_of?(self)
          raise UnexpectedMessage,
                "Expected a #{name}, but got a #{result.class.name}"
        end

        result
      rescue Nokogiri::XML::SyntaxError
        raise CorruptMessage
      end

      protected

      def known_messages
        @known_messages ||= {}
      end

      def inherited(klass)
        super
        # explicitly keep track of all messages in this base class
        Message.known_messages[klass.name.sub(/^SAML2::/, "")] = klass
      end
    end

    def initialize
      super
      @errors = []
      @id = "_#{SecureRandom.uuid}"
      @issue_instant = Time.now.utc
    end

    # (see Base#from_xml)
    def from_xml(node)
      super
      @id = nil
      @issue_instant = nil
    end

    def validate
      @errors = Schemas.protocol.validate(xml.document)
      errors
    end

    # If the XML is valid according to SAML XSDs.
    # @return [Boolean]
    def valid_schema?
      return false unless Schemas.protocol.valid?(xml.document)

      true
    end

    # (see Signable#sign)
    def sign(x509_certificate, private_key, algorithm_name = :sha256)
      super

      xml = @document.root
      # the Signature element must be right after the Issuer, so put it there
      issuer = xml.at_xpath("saml:Issuer", Namespaces::ALL)
      signature = xml.at_xpath("dsig:Signature", Namespaces::ALL)
      issuer.add_next_sibling(signature)
      self
    end

    # @return [String]
    def id
      @id ||= xml["ID"]
    end

    # @return [Time]
    def issue_instant
      @issue_instant ||= Time.parse(xml["IssueInstant"])
    end

    # @return [String, nil]
    def destination
      @destination = xml["Destination"] if xml && !instance_variable_defined?(:@destination)
      @destination
    end

    # @return [NameID, nil]
    def issuer
      @issuer ||= NameID.from_xml(xml.at_xpath("saml:Issuer", Namespaces::ALL))
    end

    protected

    # should be called from inside the specific request element
    def build(message)
      message.parent["ID"] = id
      message.parent["Version"] = "2.0"
      message.parent["IssueInstant"] = issue_instant.iso8601
      message.parent["Destination"] = destination if destination

      issuer&.build(message, element: "Issuer")
    end
  end
end
