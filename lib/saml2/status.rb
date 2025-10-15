# frozen_string_literal: true

require "saml2/base"

module SAML2
  class Status < Base
    SUCCESS   = "urn:oasis:names:tc:SAML:2.0:status:Success"
    REQUESTER = "urn:oasis:names:tc:SAML:2.0:status:Requester"
    RESPONDER = "urn:oasis:names:tc:SAML:2.0:status:Responder"
    VERSION_MISMATCH = "urn:oasis:names:tc:SAML:2.0:status:VersionMismatch"

    AUTHN_FAILED = "urn:oasis:names:tc:SAML:2.0:status:AuthnFailed"
    INVALID_ATTR_NAME_OR_VALUE = "urn:oasis:names:tc:SAML:2.0:status:InvalidAttrNameOrValue"
    INVALID_NAME_ID_POLICY = "urn:oasis:names:tc:SAML:2.0:status:InvalidNameIDPolicy"
    NO_AUTHN_CONTEXT = "urn:oasis:names:tc:SAML:2.0:status:NoAuthnContext"
    NO_AVAILABLE_IDP = "urn:oasis:names:tc:SAML:2.0:status:NoAvailableIDP"
    NO_PASSIVE = "urn:oasis:names:tc:SAML:2.0:status:NoPassive"
    NO_SUPPORTED_IDP = "urn:oasis:names:tc:SAML:2.0:status:NoSupportedIDP"
    PARTIAL_LOGOUT = "urn:oasis:names:tc:SAML:2.0:status:PartialLogout"
    PROXY_COUNT_EXCEEDED = "urn:oasis:names:tc:SAML:2.0:status:ProxyCountExceeded"
    REQUEST_DENIED = "urn:oasis:names:tc:SAML:2.0:status:RequestDenied"
    REQUEST_UNSUPPORTED = "urn:oasis:names:tc:SAML:2.0:status:RequestUnsupported"
    REQUEST_VERSION_DEPRECATED = "urn:oasis:names:tc:SAML:2.0:status:RequestVersionDeprecated"
    REQUEST_VERSION_TOO_HIGH = "urn:oasis:names:tc:SAML:2.0:status:RequestVersionTooHigh"
    REQUEST_VERSION_TOO_LOW = "urn:oasis:names:tc:SAML:2.0:status:RequestVersionTooLow"
    RESOURCE_NOT_RECOGNIZED = "urn:oasis:names:tc:SAML:2.0:status:ResourceNotRecognized"
    TOO_MANY_RESPONSES = "urn:oasis:names:tc:SAML::2.0:status:TooManyResponses"
    UNKNOWN_ATTR_PROFILE = "urn:oasis:names:tc:SAML:2.0:status:UnknownAttrProfile"
    UNKNOWN_PRINCIPAL = "urn:oasis:names:tc:SAML:2.0:status:UnknownPrincipal"
    UNSUPPORTED_BINDING = "urn:oasis:names:tc:SAML:2.0:status:UnsupportedBinding"

    TOP_LEVEL_STATUS_CODES = [SUCCESS, REQUESTER, RESPONDER, VERSION_MISMATCH].freeze

    # @return [Array<String>]
    attr_reader :codes
    # @return [String]
    attr_accessor :message, :detail

    # @param code [String]
    # @param message [String, nil]
    def initialize(code = SUCCESS, message = nil, detail = nil)
      super()
      self.codes = code
      @message = message
      @detail = detail
    end

    # (see Base#from_xml)
    def from_xml(node)
      super

      @codes.clear
      code_node = node

      loop do
        code_node = code_node.at_xpath("samlp:StatusCode", Namespaces::ALL)
        break unless code_node

        codes << code_node["Value"]
      end
      self.message = xml.at_xpath("samlp:StatusMessage", Namespaces::ALL)&.content&.strip
      self.detail = xml.at_xpath("samlp:StatusDetail", Namespaces::ALL)&.content&.strip
    end

    def code
      codes.first
    end

    def codes=(value)
      codes = Array.wrap(value)
      unless TOP_LEVEL_STATUS_CODES.include?(codes.first)
        raise ArgumentError, "Invalid top level status code #{codes.first.inspect}"
      end

      @codes = codes
    end
    alias_method :code=, :codes=

    def success?
      code == SUCCESS
    end

    # (see Base#build)
    def build(builder)
      builder["samlp"].Status do |status|
        build_code(status, codes, 0)

        status["samlp"].StatusMessage(message) if message
        status["samlp"].StatusDetail(detail) if detail
      end
    end

    private

    def build_code(builder, codes, idx)
      return if idx >= codes.length

      builder["samlp"].StatusCode(Value: codes[idx]) do |code_builder|
        build_code(code_builder, codes, idx + 1)
      end
    end
  end
end
