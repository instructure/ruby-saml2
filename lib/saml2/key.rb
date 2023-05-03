# frozen_string_literal: true

require "openssl"

require "saml2/base"
require "saml2/namespaces"

module SAML2
  # This represents the XML Signatures <KeyInfo> element, and actually contains a
  # reference to an X.509 certificate, not solely a public key.
  class KeyInfo < Base
    # @return [String] The PEM encoded certificate.
    attr_reader :x509
    # @return [OpenSSL::PKey::PKey] An RSA Public Key
    attr_accessor :key

    # @param x509 [String] The PEM encoded certificate.
    def initialize(x509 = nil)
      super()
      self.x509 = x509
    end

    # (see Base#from_xml)
    def from_xml(node)
      self.x509 = node.at_xpath("dsig:X509Data/dsig:X509Certificate", Namespaces::ALL)&.content&.strip
      return unless (rsa_key_value = node.at_xpath("dsig:KeyValue/dsig:RSAKeyValue", Namespaces::ALL))

      modulus = crypto_binary_to_integer(rsa_key_value.at_xpath("dsig:Modulus", Namespaces::ALL)&.content&.strip)
      exponent = crypto_binary_to_integer(rsa_key_value.at_xpath("dsig:Exponent", Namespaces::ALL)&.content&.strip)
      return unless modulus && exponent

      @key = OpenSSL::PKey::RSA.new
      key.set_key(modulus, exponent, nil)
    end

    def x509=(value)
      @x509 = value&.gsub(/\w*-+(BEGIN|END) CERTIFICATE-+\w*/, "")&.strip
    end

    # @return [OpenSSL::X509::Certificate]
    def certificate
      return nil if x509.nil?

      @certificate ||= OpenSSL::X509::Certificate.new(Base64.decode64(x509))
    end

    # @return [OpenSSL::PKey::PKey]
    def public_key
      key || certificate&.public_key
    end

    # Formats a fingerprint as all lowercase, with a : every two characters,
    # stripping all non-hexadecimal characters.
    # @param fingerprint [String]
    # @return [String]
    def self.format_fingerprint(fingerprint)
      fingerprint.downcase.gsub(/[^0-9a-f]/, "").gsub(/(\h{2})(?=\h)/, '\1:')
    end

    # @return [String]
    def fingerprint
      return nil unless certificate

      @fingerprint ||= self.class.format_fingerprint(Digest::SHA1.hexdigest(certificate.to_der))
    end

    # (see Base#build)
    def build(builder)
      builder["dsig"].KeyInfo do |key_info|
        if x509
          key_info["dsig"].X509Data do |x509_data|
            x509_data["dsig"].X509Certificate(x509)
          end
        end
        if key.is_a?(OpenSSL::PKey::RSA)
          key_info["dsig"].KeyValue do |key_value|
            key_value["dsig"].RSAKeyValue do |rsa_key_value|
              rsa_key_value["dsig"].Modulus(Base64.encode64(key.n.to_s(2)))
              rsa_key_value["dsig"].Exponent(Base64.encode64(key.e.to_s(2)))
            end
          end
        end
      end
    end

    private

    def crypto_binary_to_integer(str)
      return nil unless str

      OpenSSL::BN.new(Base64.decode64(str), 2)
    end
  end

  class KeyDescriptor < KeyInfo
    module Type
      ENCRYPTION = "encryption"
      SIGNING    = "signing"
    end

    class EncryptionMethod < Base
      module Algorithm
        AES128_CBC = "http://www.w3.org/2001/04/xmlenc#aes128-cbc"
      end

      # @see Algorithm
      # @return [String]
      attr_accessor :algorithm
      # @return [Integer]
      attr_accessor :key_size

      # @param algorithm [String]
      # @param key_size [Integer]
      def initialize(algorithm = Algorithm::AES128_CBC, key_size = 128)
        super()
        @algorithm = algorithm
        @key_size = key_size
      end

      # (see Base#from_xml)
      def from_xml(node)
        self.algorithm = node["Algorithm"]
        self.key_size = node.at_xpath("xenc:KeySize", Namespaces::ALL)&.content&.to_i
      end

      # (see Base#build)
      def build(builder)
        builder["md"].EncryptionMethod("Algorithm" => algorithm) do |encryption_method|
          encryption_method["xenc"].KeySize(key_size) if key_size
        end
      end
    end

    # @see Type
    # @return [String]
    attr_accessor :use
    # @return [Array<EncryptionMethod>]
    attr_accessor :encryption_methods

    # (see Base#from_xml)
    def from_xml(node)
      super(node.at_xpath("dsig:KeyInfo", Namespaces::ALL))
      self.use = node["use"]
      self.encryption_methods = load_object_array(node, "md:EncryptionMethod", EncryptionMethod)
    end

    # @param x509 [String] The PEM encoded certificate.
    # @param use optional [String] See {Type}
    # @param encryption_methods [Array<EncryptionMethod>]
    def initialize(x509 = nil, use = nil, encryption_methods = [])
      super()
      @use = use
      self.x509 = x509
      @encryption_methods = encryption_methods
    end

    def encryption?
      use.nil? || use == Type::ENCRYPTION
    end

    def signing?
      use.nil? || use == Type::SIGNING
    end

    # (see Base#build)
    def build(builder)
      builder["md"].KeyDescriptor do |key_descriptor|
        key_descriptor.parent["use"] = use if use
        super(key_descriptor)
        encryption_methods.each do |method|
          method.build(key_descriptor)
        end
      end
    end
  end

  # @deprecated Deprecated alias for KeyDescriptor
  Key = KeyDescriptor
end
