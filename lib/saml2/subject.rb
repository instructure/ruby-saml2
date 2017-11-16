require 'saml2/name_id'
require 'saml2/namespaces'

module SAML2
  class Subject < Base
    attr_writer :name_id
    attr_writer :confirmations

    def initialize
      @confirmations = []
    end

    def from_xml(node)
      super
      @confirmations = nil
    end

    def name_id
      if xml && !instance_variable_defined?(:@name_id)
        @name_id = NameID.from_xml(xml.at_xpath('saml:NameID', Namespaces::ALL))
      end
      @name_id
    end

    def confirmation
      Array.wrap(confirmations).first
    end

    def confirmation=(value)
      @confirmations = [value]
    end

    def confirmations
      @confirmations ||= load_object_array(xml, 'saml:SubjectConfirmation', Confirmation)
    end

    def build(builder)
      builder['saml'].Subject do |subject|
        name_id.build(subject) if name_id
        Array(confirmations).each do |confirmation|
          confirmation.build(subject)
        end
      end
    end

    class Confirmation < Base
      module Methods
        BEARER         = 'urn:oasis:names:tc:SAML:2.0:cm:bearer'.freeze
        HOLDER_OF_KEY  = 'urn:oasis:names:tc:SAML:2.0:cm:holder-of-key'.freeze
        SENDER_VOUCHES = 'urn:oasis:names:tc:SAML:2.0:cm:sender-vouches'.freeze
      end

      attr_accessor :method, :not_before, :not_on_or_after, :recipient, :in_response_to

      def from_xml(node)
        super
        self.method = node['Method']
        confirmation_data = node.at_xpath('saml:SubjectConfirmationData', Namespaces::ALL)
        if confirmation_data
          self.not_before = Time.parse(confirmation_data['NotBefore']) if confirmation_data['NotBefore']
          self.not_on_or_after = Time.parse(confirmation_data['NotOnOrAfter']) if confirmation_data['NotOnOrAfter']
          self.recipient = confirmation_data['Recipient']
          self.in_response_to = confirmation_data['InResponseTo']
        end
      end

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
