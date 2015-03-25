require 'saml2/conditions'

module SAML2
  class Assertion
    attr_reader :id, :issue_instant, :conditions, :statements
    attr_accessor :issuer, :subject

    def initialize
      @id = "_#{SecureRandom.uuid}"
      @issue_instant = Time.now.utc
      @statements = []
      @conditions = Conditions.new
    end

    def sign(x509_certificate, private_key, algorithm_name = :sha256)
      to_xml

      @xml.set_id_attribute('ID')
      @xml.sign!(cert: x509_certificate, key: private_key, digest_alg: algorithm_name.to_s, signature_alg: "rsa-#{algorithm_name}", uri: "##{id}")
      # the Signature element must be right after the Issuer, so put it there
      issuer = @xml.at_xpath("saml:Issuer", Namespaces::ALL)
      signature = @xml.at_xpath("dsig:Signature", Namespaces::ALL)
      issuer.add_next_sibling(signature)
      self
    end

    def to_xml
      @xml ||= Nokogiri::XML::Builder.new do |builder|
        builder['saml'].Assertion(
            'xmlns:saml' => Namespaces::SAML,
            ID: id,
            Version: '2.0',
            IssueInstant: issue_instant.iso8601
        ) do |builder|
          issuer.build(builder, element: 'Issuer')

          subject.build(builder)

          conditions.build(builder)
          statements.each { |stmt| stmt.build(builder) }
        end
      end.doc.root
    end
  end
end
