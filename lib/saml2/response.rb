require 'nokogiri-xmlsec'
require 'time'

require 'saml2/assertion'
require 'saml2/authn_statement'
require 'saml2/status_response'
require 'saml2/subject'

module SAML2
  class Response < StatusResponse
    attr_reader :assertions

    # Respond to an {AuthnRequest}
    # @param authn_request [AuthnRequest]
    # @param issuer [NameID]
    # @param name_id [NameID] The Subject
    # @param attributes optional [Hash<String => String>, Array<Attribute>]
    # @return [Response]
    def self.respond_to(authn_request, issuer, name_id, attributes = nil)
      response = initiate(nil, issuer, name_id)
      response.in_response_to = authn_request.id
      response.destination = authn_request.assertion_consumer_service.location
      confirmation = response.assertions.first.subject.confirmation
      confirmation.in_response_to = authn_request.id
      confirmation.recipient = response.destination
      if attributes && authn_request.attribute_consuming_service
        statement = authn_request.attribute_consuming_service.create_statement(attributes)
        response.assertions.first.statements << statement if statement
      end
      response.assertions.first.conditions << Conditions::AudienceRestriction.new(authn_request.issuer.id)

      response
    end

    # Begin an IdP Initiated login
    # @param service_provider [ServiceProvider]
    # @param issuer [NameID]
    # @param name_id [NameID] The subject
    # @param attributes optional [Hash<String => String>, Array<Attribute>]
    # @return [Response]
    def self.initiate(service_provider, issuer, name_id, attributes = nil)
      response = new
      response.issuer = issuer
      response.destination = service_provider.assertion_consumer_services.default.location if service_provider
      assertion = Assertion.new
      assertion.subject = Subject.new
      assertion.subject.name_id = name_id
      assertion.subject.confirmation = Subject::Confirmation.new
      assertion.subject.confirmation.method = Subject::Confirmation::Methods::BEARER
      assertion.subject.confirmation.not_on_or_after = Time.now.utc + 30
      assertion.subject.confirmation.recipient = response.destination if response.destination
      assertion.issuer = issuer
      assertion.conditions.not_before = Time.now.utc - 5
      assertion.conditions.not_on_or_after = Time.now.utc + 30
      authn_statement = AuthnStatement.new
      authn_statement.authn_instant = response.issue_instant
      authn_statement.authn_context_class_ref = AuthnStatement::Classes::UNSPECIFIED
      assertion.statements << authn_statement
      if attributes && service_provider.attribute_consuming_services.default
        statement = service_provider.attribute_consuming_services.default.create_statement(attributes)
        assertion.statements << statement if statement
      end
      response.assertions << assertion
      response
    end

    def initialize
      super
      @assertions = []
    end

    # (see Base#from_xml)
    def from_xml(node)
      super
      remove_instance_variable(:@assertions)
    end

    # @return [Array<Assertion>]
    def assertions
      unless instance_variable_defined?(:@assertions)
        @assertions = load_object_array(xml, 'saml:Assertion', Assertion)
      end
      @assertions
    end

    # (see Signable#sign)
    # Signs each assertion.
    def sign(x509_certificate, private_key, algorithm_name = :sha256)
      assertions.each { |assertion| assertion.sign(x509_certificate, private_key, algorithm_name) }
      # make sure we no longer pretty print this object
      @pretty = false
      nil
    end

    private

    def build(builder)
      builder['samlp'].Response(
        'xmlns:samlp' => Namespaces::SAMLP,
        'xmlns:saml' => Namespaces::SAML
      ) do |response|
        super(response)

        assertions.each do |assertion|
          # we can't just call build, because it may already
          # be signed as a separate message, so call to_xml to
          # get the cached signed result
          response.parent << assertion.to_xml.root
        end
      end
    end
  end
end
