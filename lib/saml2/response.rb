# frozen_string_literal: true

require "nokogiri-xmlsec"
require "time"

require "saml2/assertion"
require "saml2/authn_statement"
require "saml2/status_response"
require "saml2/subject"

module SAML2
  class Response < StatusResponse
    # Respond to an {AuthnRequest}
    #
    # {AuthnRequest#resolve} needs to have been previously called on the {AuthnRequest}.
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

    # Validates a response is well-formed, signed, and optionally decrypts it
    #
    # @param service_provider [Entity]
    #   The metadata object for the {ServiceProvider} receiving this
    #   {Response}. The first {ServiceProvider} in the {Entity} is used.
    # @param identity_provider [Entity]
    #   The metadata object for the {IdentityProvider} the {Response} is
    #   being received from. The first {IdentityProvider} in the {Entity} is
    #   used.
    # @param verification_time optional [DateTime]
    #   Validate timestamps (signing certificate validity, issued at, etc.) as of
    #   this point in time.
    # @param ignore_audience_condition optional [true, false]
    #   Don't validate any Audience conditions.
    def validate(service_provider:,
                 identity_provider:,
                 verification_time: nil,
                 ignore_audience_condition: false)
      raise ArgumentError, "service_provider should be an Entity object" unless service_provider.is_a?(Entity)

      unless (sp = service_provider.service_providers.first)
        raise ArgumentError,
              "service_provider should have at least one service_provider role"
      end

      # validate the schema
      super()
      return errors unless errors.empty?

      if verification_time.nil?
        verification_time = Time.now.utc
        # they issued it in the (near) future according to our clock;
        # use their clock instead
        if issue_instant > verification_time && issue_instant < verification_time + (5 * 60)
          verification_time = issue_instant
        end
      end

      # not finding the issuer is not exceptional
      if identity_provider.nil?
        errors << "could not find issuer of response"
        return errors
      end

      # getting the wrong data type is exceptional, and we should raise an error
      raise ArgumentError, "identity_provider should be an Entity object" unless identity_provider.is_a?(Entity)

      unless (idp = identity_provider.identity_providers.first)
        raise ArgumentError,
              "identity_provider should have at least one identity_provider role"
      end

      issuer = self.issuer || assertions.first&.issuer
      unless identity_provider.entity_id == issuer&.id
        errors << "received unexpected message from '#{issuer&.id}'; " \
                  "expected it to be from '#{identity_provider.entity_id}'"
        return errors
      end

      certificates = idp.signing_keys.filter_map(&:certificate)
      keys = idp.signing_keys.filter_map(&:key)
      if idp.fingerprints.empty? && certificates.empty? && keys.empty?
        errors << "could not find certificate to validate message"
        return errors
      end

      if signed?
        unless (signature_errors = validate_signature(key: keys,
                                                      fingerprint: idp.fingerprints,
                                                      cert: certificates)).empty?
          return errors.concat(signature_errors)
        end

        response_signed = true
      end

      assertion = assertions.first

      # this might be nil, if the assertion was encrypted
      if assertion&.signed?
        unless (signature_errors = assertion.validate_signature(key: keys,
                                                                fingerprint: idp.fingerprints,
                                                                cert: certificates)).empty?
          return errors.concat(signature_errors)
        end

        assertion_signed = true
      end

      find_decryption_key = lambda do |embedded_certificates|
        key = nil
        embedded_certificates.each do |cert_info|
          cert = case cert_info
                 when OpenSSL::X509::Certificate then cert_info
                 when Hash then sp.encryption_keys.map(&:certificate).find { |c| c.serial == cert_info[:serial] }
                 end
          next unless cert

          key = sp.private_keys.find { |k| cert.check_private_key(k) }
          break if key
        end
        unless key
          # couldn't figure out which key to use; just try them all
          next sp.private_keys
        end

        key
      end

      unless sp.private_keys.empty?
        begin
          decypted_anything = decrypt(&find_decryption_key)
        rescue XMLSec::DecryptionError
          errors << "unable to decrypt response"
          return errors
        end

        if decypted_anything
          # have to re-validate the schema, since we just replaced content
          super()
          # also clear this cached value so that we can see cached assertions
          remove_instance_variable(:@assertions)
          return errors unless errors.empty?
        end
      end

      unless status.success?
        errors << "response is not successful: #{status}"
        return errors
      end

      assertion ||= assertions.first
      unless assertion
        errors << "no assertion found"
        return errors
      end

      # if we didn't previously check the assertion's signature (because it was encrypted)
      # check it now
      if assertion.signed? && !assertion_signed
        unless (signature_errors = assertion.validate_signature(fingerprint: idp.fingerprints,
                                                                cert: certificates)).empty?
          return errors.concat(signature_errors)
        end

        assertion_signed = true
      end

      # only do our own issue instant validation if the assertion
      # doesn't mandate any
      if !assertion.conditions&.not_on_or_after && (assertion.issue_instant + (5 * 60) < verification_time ||
           assertion.issue_instant - (5 * 60) > verification_time)
        errors << "assertion not recently issued"
        return errors
      end

      if assertion.conditions &&
         !(condition_errors = assertion.conditions.validate(
           verification_time: verification_time,
           audience: service_provider.entity_id,
           ignore_audience_condition: ignore_audience_condition
         )).empty?
        return errors.concat(condition_errors)
      end

      if !response_signed && !assertion_signed
        errors << "neither response nor assertion were signed"
        return errors
      end

      unless sp.private_keys.empty?
        begin
          decypted_anything = assertion.decrypt(&find_decryption_key)
        rescue XMLSec::DecryptionError
          errors << "unable to decrypt assertion"
          return errors
        end

        if decypted_anything
          super()
          return errors unless errors.empty?
        end
      end

      # no error
      errors
    end

    # @return [Array<Assertion>]
    def assertions
      @assertions = load_object_array(xml, "saml:Assertion", Assertion) unless instance_variable_defined?(:@assertions)
      @assertions
    end

    # (see Signable#sign)
    # Signs each assertion.
    def sign(x509_certificate, private_key, algorithm_name = :sha256)
      # make sure we no longer pretty print this object
      @pretty = false

      # if there are no assertions (encrypted?), just sign the response itself
      return super if assertions.empty?

      assertions.each { |assertion| assertion.sign(x509_certificate, private_key, algorithm_name) }
      self
    end

    private

    def build(builder)
      builder["samlp"].Response(
        "xmlns:samlp" => Namespaces::SAMLP,
        "xmlns:saml" => Namespaces::SAML
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
