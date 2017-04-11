require 'saml2/namespaces'

module SAML2
  class Key
    module Type
      ENCRYPTION = 'encryption'.freeze
      SIGNING    = 'signing'.freeze
    end

    class EncryptionMethod
      module Algorithm
        AES128_CBC = 'http://www.w3.org/2001/04/xmlenc#aes128-cbc'.freeze
      end

      attr_accessor :algorithm, :key_size

      def initialize(algorithm = Algorithm::AES128_CBC, key_size = 128)
        @algorithm, @key_size = algorithm, key_size
      end

      def build(builder)
        builder['md'].EncryptionMethod('Algorithm' => algorithm) do |encryption_method|
          encryption_method['xenc'].KeySize(key_size) if key_size
        end
      end
    end

    attr_accessor :use, :x509, :encryption_methods

    def self.from_xml(node)
      return nil unless node

      x509 = node.at_xpath('dsig:KeyInfo/dsig:X509Data/dsig:X509Certificate', Namespaces::ALL)
      methods = node.xpath('xenc:EncryptionMethod', Namespaces::ALL)
      new(x509 && x509.content.strip, node['use'], methods.map { |m| m['Algorithm'] })
    end

    def initialize(x509, use = nil, encryption_methods = [])
      @use, @x509, @encryption_methods = use, x509.gsub(/\w*-+(BEGIN|END) CERTIFICATE-+\w*/, "").strip, encryption_methods
    end

    def encryption?
      use.nil? || use == Type::ENCRYPTION
    end

    def signing?
      use.nil? || use == Type::SIGNING
    end

    def certificate
      @certificate ||= OpenSSL::X509::Certificate.new(Base64.decode64(x509))
    end

    def fingerprint
      @fingerprint ||= Digest::SHA1.hexdigest(certificate.to_der).gsub(/(\h{2})(?=\h)/, '\1:')
    end

    def build(builder)
      builder['md'].KeyDescriptor do |key_descriptor|
        key_descriptor.parent['use'] = use if use
        key_descriptor['dsig'].KeyInfo do |key_info|
          key_info['dsig'].X509Data do |x509_data|
            x509_data['dsig'].X509Certificate(x509)
          end
        end
        encryption_methods.each do |method|
          method.build(key_descriptor)
        end
      end
    end
  end
end
