require 'nokogiri-xmlsec'
require 'securerandom'
require 'time'

require 'saml2/assertion'
require 'saml2/authn_statement'
require 'saml2/base'
require 'saml2/subject'

module SAML2
  class Response < Base
    module Status
      SUCCESS = "urn:oasis:names:tc:SAML:2.0:status:Success".freeze
    end

    attr_reader :id, :issue_instant, :assertions
    attr_accessor :issuer, :in_response_to, :destination, :status_code

    def self.respond_to(authn_request, issuer, name_id, attributes = [])
      response = initiate(nil, issuer, name_id)
      response.in_response_to = authn_request.id
      response.destination = authn_request.assertion_consumer_service.location
      confirmation = response.assertions.first.subject.confirmation
      confirmation.in_response_to = authn_request.id
      confirmation.recipient = response.destination
      if authn_request.attribute_consuming_service
        response.assertion.first.statements << authn_request.attribute_consuming_service.create_statement(attributes)
      end
      response
    end

    def self.initiate(service_provider, issuer, name_id)
      response = new
      response.issuer = issuer
      response.destination = service_provider.assertion_consumer_services.default.location if service_provider
      assertion = Assertion.new
      assertion.subject = Subject.new
      assertion.subject.name_id = name_id
      assertion.subject.confirmation = Subject::Confirmation.new
      assertion.subject.confirmation.method = Subject::Confirmation::Methods::BEARER
      assertion.subject.confirmation.not_before = Time.now.utc
      assertion.subject.confirmation.not_on_or_after = Time.now.utc + 30
      assertion.subject.confirmation.recipient = response.destination if response.destination
      assertion.issuer = issuer
      authn_statement = AuthnStatement.new
      authn_statement.authn_instant = response.issue_instant
      authn_statement.authn_context_class_ref = AuthnStatement::Classes::UNSPECIFIED
      assertion.statements << authn_statement
      response.assertions << assertion
      response
    end

    def initialize
      @id = "_#{SecureRandom.uuid}"
      @status_code = Status::SUCCESS
      @issue_instant = Time.now.utc
      @assertions = []
    end

    def sign(*args)
      assertions.each { |assertion| assertion.sign(*args) }
    end

    private
    def build(builder)
      builder['samlp'].Response(
        'xmlns:samlp' => Namespaces::SAMLP,
        ID: id,
        Version: '2.0',
        IssueInstant: issue_instant.iso8601,
        Destination: destination
      ) do |builder|
        builder.parent['InResponseTo'] = in_response_to if in_response_to

        issuer.build(builder, element: 'Issuer', include_namespace: true) if issuer

        builder['samlp'].Status do |builder|
          builder['samlp'].StatusCode(Value: status_code)
          end

        assertions.each do |assertion|
          builder.parent << assertion.to_xml
        end
      end
    end
  end
end
