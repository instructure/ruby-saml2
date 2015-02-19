require 'nokogiri-xmlsec'
require 'securerandom'
require 'time'

require 'saml2/assertion'
require 'saml2/base'
require 'saml2/subject'

module SAML2
  class Response < Base
    module Status
      SUCCESS = "urn:oasis:names:tc:SAML:2.0:status:Success".freeze
    end

    attr_reader :id, :issue_instant, :assertions
    attr_accessor :issuer, :in_response_to, :destination, :status_code

    def self.respond_to(authn_request, issuer, name_id)
      response = new
      response.in_response_to = authn_request.id
      response.destination = authn_request.assertion_consumer_service.location
      response.issuer = issuer
      assertion = Assertion.new(response.document)
      assertion.subject = Subject.new
      assertion.subject.name_id = name_id
      assertion.issuer = issuer
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

    def to_xml
      return document if @serialized
      @serialized = true
      document << Nokogiri::XML::Builder.detached(document) do |builder|
        builder['samlp'].Response(
          'xmlns:samlp' => Namespaces::SAMLP,
          ID: id,
          Version: '2.0',
          IssueInstant: issue_instant.iso8601,
          Destination: destination,
          InResponseTo: in_response_to
        ) do |builder|
          issuer.build(builder, element: 'Issuer', include_namespace: true) if issuer

          builder['samlp'].Status do |builder|
            builder['samlp'].StatusCode(Value: status_code)
            end

          assertions.each do |assertion|
            builder.parent << assertion.to_xml
          end
        end
      end
      document
    end
  end
end
