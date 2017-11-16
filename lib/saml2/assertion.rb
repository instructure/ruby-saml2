require 'saml2/conditions'

module SAML2
  class Assertion < Message
    attr_writer :statements, :subject

    def initialize
      super
      @statements = []
      @conditions = Conditions.new
    end

    def from_xml(node)
      super
      @conditions = nil
      @statements = nil
    end

    def sign(x509_certificate, private_key, algorithm_name = :sha256)
      to_xml

      xml = @document.root
      xml.set_id_attribute('ID')
      xml.sign!(cert: x509_certificate, key: private_key, digest_alg: algorithm_name.to_s, signature_alg: "rsa-#{algorithm_name}", uri: "##{id}")
      # the Signature element must be right after the Issuer, so put it there
      issuer = xml.at_xpath("saml:Issuer", Namespaces::ALL)
      signature = xml.at_xpath("dsig:Signature", Namespaces::ALL)
      issuer.add_next_sibling(signature)
      self
    end

    def subject
      if xml && !instance_variable_defined?(:@subject)
        @subject = Subject.from_xml(xml.at_xpath('saml:Subject', Namespaces::ALL))
      end
      @subject
    end

    def conditions
      @conditions ||= Conditions.from_xml(xml.at_xpath('saml:Conditions', Namespaces::ALL))
    end

    def statements
      @statements ||= load_object_array(xml, 'saml:AuthnStatement|saml:AttributeStatement')
    end

    def build(builder)
      builder['saml'].Assertion(
          'xmlns:saml' => Namespaces::SAML
      ) do |assertion|
        super(assertion)

        subject.build(assertion)

        conditions.build(assertion)

        statements.each { |stmt| stmt.build(assertion) }
      end
    end
  end
end
