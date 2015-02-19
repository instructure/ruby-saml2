module SAML2
  class Assertion
    attr_reader :id, :issue_instant
    attr_accessor :issuer, :subject

    def initialize(document)
      @document = document
      @id = "_#{SecureRandom.uuid}"
      @issue_instant = Time.now.utc
    end

    def sign(x509_certificate, private_key, algorithm_name = :sha256)
      to_xml

      # the assertion has to be in the document _somewhere_ to sign it
      # (cause xmlsec will do an xpath on the document to resolve the
      # reference)
      unless @xml.parent
        needs_unlink = true
        if @document.root
          @document.root << @xml
        else
          @document << @xml
        end
      end

      begin
        @xml.set_id_attribute('ID')
        @xml.sign!(cert: x509_certificate, key: private_key, digest_alg: algorithm_name.to_s, signature_alg: "rsa-#{algorithm_name}", uri: "##{id}")
      ensure
        @xml.unlink if needs_unlink
      end
      self
    end

    def to_xml
      @xml ||= Nokogiri::XML::Builder.detached(@document) do |builder|
        builder['saml'].Assertion(
            'xmlns:saml' => Namespaces::SAML,
            ID: id,
            Version: '2.0',
            IssueInstant: issue_instant.iso8601
        ) do |builder|
          issuer.build(builder, element: 'Issuer')

          builder['saml'].Subject do |builder|
            subject.name_id.build(builder)
          end
        end
      end.first
    end
  end
end
