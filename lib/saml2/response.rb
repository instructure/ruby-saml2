require 'nokogiri-xmlsec'
require 'securerandom'
require 'time'

module SAML2
  class Response
    module Status
      SUCCESS = "urn:oasis:names:tc:SAML:2.0:status:Success".freeze
    end

    attr_reader :id, :assertion_id, :issue_instant
    attr_accessor :issuer, :in_response_to, :destination, :status_code, :name_id

    def self.respond_to(authn_request)
      response = new
      response.in_response_to = authn_request.id
      response.destination = authn_request.assertion_consumer_service.location
      response
    end

    def initialize
      @id = "_#{SecureRandom.uuid}"
      @assertion_id = "_#{SecureRandom.uuid}"
      @issue_instant = Time.now.utc
      @status_code = Status::SUCCESS
    end

    def sign(x509_certificate, private_key, algorithm_name = :sha256)
      raise "XML already generated" if @document
      response
      @assertion.set_id_attribute('ID')
      @assertion.sign!(cert: x509_certificate, key: private_key, digest_alg: algorithm_name.to_s, signature_alg: "rsa-#{algorithm_name}", uri: "##{assertion_id}")
      self
    end

    def to_xml
      # make sure to not FORMAT it - it breaks the signature!
      response.to_xml(save_with: Nokogiri::XML::Node::SaveOptions::AS_XML)
    end

    private

    def response
      @document ||= Nokogiri::XML::Builder.new do |xml|
        xml['samlp'].Response(
          'xmlns:samlp' => Namespaces::SAMLP,
          ID: id,
          Version: '2.0',
          IssueInstant: issue_instant.iso8601,
          Destination: destination,
          InResponseTo: in_response_to
        ) do |xml|
            xml['saml'].Issuer(issuer,
                'xmlns:saml' => Namespaces::SAML
            )

            xml['samlp'].Status do |xml|
              xml['samlp'].StatusCode(Value: status_code)
            end

            assertion(xml)
        end
      end.doc
    end

    def assertion(xml)
      xml['saml'].Assertion(
          'xmlns:saml' => Namespaces::SAML,
          ID: assertion_id,
          Version: '2.0',
          IssueInstant: issue_instant.iso8601
      ) do |xml|
        # save this off so that we can access it directly for signing
        @assertion = xml.parent

        xml['saml'].Issuer(issuer)

        xml['saml'].Subject do |xml|
          xml['saml'].NameID(name_id.id,
              Format: name_id.format
          )
        end
      end
    end
  end
end
