require 'saml2/name_id'
require 'saml2/namespaces'

module SAML2
  class Subject < Base
    attr_writer :name_id
    attr_accessor :confirmation

    def name_id
      if xml && !instance_variable_defined?(:@name_id)
        @name_id = NameID.from_xml(node.at_xpath('saml:NameID', Namespaces::ALL))
      end
      @name_id
    end

    def build(builder)
      builder['saml'].Subject do |subject|
        name_id.build(subject) if name_id
        confirmation.build(subject) if confirmation
      end
    end

    class Confirmation < Base
      module Methods
        BEARER         = 'urn:oasis:names:tc:SAML:2.0:cm:bearer'.freeze
        HOLDER_OF_KEY  = 'urn:oasis:names:tc:SAML:2.0:cm:holder-of-key'.freeze
        SENDER_VOUCHES = 'urn:oasis:names:tc:SAML:2.0:cm:sender-vouches'.freeze
      end

      attr_accessor :method, :not_before, :not_on_or_after, :recipient, :in_response_to

      def build(builder)
        builder['saml'].SubjectConfirmation('Method' => method) do |subject_confirmation|
          if in_response_to ||
              recipient ||
              not_before ||
              not_on_or_after
            subject_confirmation['saml'].SubjectConfirmationData do |subject_confirmation_data|
              subject_confirmation_data.parent['NotBefore'] = not_before.iso8601 if not_before
              subject_confirmation_data.parent['NotOnOrAfter'] = not_on_or_after.iso8601 if not_on_or_after
              subject_confirmation_data.parent['Recipient'] = recipient if recipient
              subject_confirmation_data.parent['InResponseTo'] = in_response_to if in_response_to
            end
          end
        end
      end
    end
  end
end
