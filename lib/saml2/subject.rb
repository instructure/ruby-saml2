require 'saml2/name_id'
require 'saml2/namespaces'

module SAML2
  class Subject
    attr_accessor :name_id, :confirmation

    def self.from_xml(node)
      return nil unless node
      subject = new
      subject.name_id = NameID.from_xml(node.at_xpath('saml:NameID', Namespaces::ALL))

      subject
    end

    def build(builder)
      builder['saml'].Subject do |builder|
        name_id.build(builder) if name_id
        confirmation.build(builder) if confirmation
      end
    end

    class Confirmation
      module Methods
        BEARER         = 'urn:oasis:names:tc:SAML:2.0:cm:bearer'.freeze
        HOLDER_OF_KEY  = 'urn:oasis:names:tc:SAML:2.0:cm:holder-of-key'.freeze
        SENDER_VOUCHES = 'urn:oasis:names:tc:SAML:2.0:cm:sender-vouches'.freeze
      end

      attr_accessor :method, :not_before, :not_on_or_after, :recipient, :in_response_to

      def build(builder)
        builder['saml'].SubjectConfirmation('Method' => method) do |builder|
          if in_response_to ||
              recipient ||
              not_before ||
              not_on_or_after
            builder['saml'].SubjectConfirmationData do |builder|
              builder.parent['NotBefore'] = not_before.iso8601 if not_before
              builder.parent['NotOnOrAfter'] = not_on_or_after.iso8601 if not_on_or_after
              builder.parent['Recipient'] = recipient if recipient
              builder.parent['InResponseTo'] = in_response_to if in_response_to
            end
          end
        end
      end
    end
  end
end
