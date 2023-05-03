# frozen_string_literal: true

require_relative "../spec_helper"

module SAML2
  describe Response do
    let(:sp_entity) { Entity.parse(fixture("service_provider.xml")) }
    let(:sp) { sp_entity.roles.first }

    let(:request) do
      request = AuthnRequest.parse(fixture("authnrequest.xml"))
      request.resolve(sp)
      request
    end

    let(:response) do
      Response.respond_to(request,
                          NameID.new("issuer"),
                          NameID.new("jacob", NameID::Format::PERSISTENT))
    end

    it "should generate valid XML" do
      xml = response.to_s
      expect(Schemas.protocol.validate(Nokogiri::XML(xml))).to eq []
    end

    def freeze_response
      response.instance_variable_set(:@id, "_9a15e699-2d04-4ba7-a521-cfa4dcd21f44")
      assertion = response.assertions.first
      assertion.instance_variable_set(:@id, "_cdfc3faf-90ad-462f-880d-677483210684")
      response.instance_variable_set(:@issue_instant, Time.parse("2015-02-12T22:51:29Z"))
      assertion.instance_variable_set(:@issue_instant, Time.parse("2015-02-12T22:51:29Z"))
      assertion.conditions.not_before = Time.parse("2015-02-12T22:51:24Z")
      assertion.conditions.not_on_or_after = Time.parse("2015-02-12T22:51:59Z")
      assertion.statements.first.authn_instant = Time.parse("2015-02-12T22:51:29Z")
      confirmation = assertion.subject.confirmation
      confirmation.not_on_or_after = Time.parse("2015-02-12T22:54:29Z")
      confirmation.recipient = response.destination
      confirmation.in_response_to = response.in_response_to
    end

    it "should generate a valid signature" do
      freeze_response
      response.sign(fixture("certificate.pem"), fixture("privatekey.key"))
      expect(Schemas.protocol.validate(response.to_xml)).to eq []
      # verifiable on the command line with:
      # xmlsec1 --verify --pubkey-cert-pem certificate.pem --privkey-pem privatekey.key \
      #   --id-attr:ID urn:oasis:names:tc:SAML:2.0:assertion:Assertion response_signed.xml
      expect(response.to_s).to eq fixture("response_signed.xml")
    end

    it "should generate a valid signature when attributes are present" do
      freeze_response
      response.assertions.first.statements <<
        sp.attribute_consuming_services.default.create_statement("givenName" => "cody")
      response.sign(fixture("certificate.pem"), fixture("privatekey.key"))
      expect(response.to_s).to eq fixture("response_with_attribute_signed.xml")
    end

    it "should generate valid XML for IdP initiated response" do
      response = Response.initiate(sp,
                                   NameID.new("issuer"),
                                   NameID.new("jacob", NameID::Format::PERSISTENT))
      expect(Schemas.protocol.validate(Nokogiri::XML(response.to_s))).to eq []
    end

    it "parses a serialized assertion" do
      response2 = Message.parse(response.to_s)
      expect(response2.in_response_to).not_to be_nil
      expect(response2.in_response_to).to eq response.in_response_to
      expect(response2.assertions.length).to eq 1
      expect(response2.assertions.first.subject.name_id.id).to eq "jacob"
    end

    it "doesn't validate a response with XSLT transforms" do
      response = Response.parse(fixture("xslt-transform-response.xml"))
      expect(response).to be_valid_schema
      expect(response.assertions.first.valid_signature?(
               fingerprint: "bc71f7bacb36011694405dd0e2beafcc069de45f"
             )).to be false
    end

    it "doesn't validate a response with external URI reference in the signature" do
      response = Response.parse(fixture("external-uri-reference-response.xml"))
      expect(response).to be_valid_schema
      expect(response.assertions.first.valid_signature?(
               fingerprint: "bc71f7bacb36011694405dd0e2beafcc069de45f"
             )).to be false
    end

    it "can decrypt an EncryptedAssertion" do
      # verifiable on the command line with:
      # xmlsec1 decrypt --privkey-pem privatekey.key response_with_encrypted_assertion.xml
      response = Response.parse(fixture("response_with_encrypted_assertion.xml"))
      expect(response.decrypt(fixture("privatekey.key"))).to be true
      expect(response.assertions.length).to eq 1
      expect(response.assertions.first.subject.name_id.id).to eq "jacob"
    end

    it "allows non-ascii characters in attributes" do
      response = Response.parse(fixture("test6-response.xml"))

      attributes = response.assertions.first.attribute_statements.first.to_h
      expect(attributes["eduPersonAffiliation"]).to eq "member"
      expect(attributes["givenName"]).to eq "Canvas"
      expect(attributes["displayName"]).to eq "Canvas Üser"
    end

    # see CVE-2017-11428
    it "returns the full content of the NameID, even if a comment-insertion " \
       "attack allows it to still validate the signature" do
      response = Response.parse(fixture("test7-response.xml"))
      # this file is a copy of test6-response.xml, with a comment inserted into the NameID

      # the signature is still valid (we have to set a weird verification time because the response
      # was signed with an expired signature)
      expect(response.validate_signature(fingerprint: "afe71c28ef740bc87425be13a2263d37971da1f9")).to eq []

      # the comment is ignored, but doesn't truncate the nameid
      expect(response.assertions.first.subject.name_id.id).to eq "testuser@example.com"
    end

    it "doesn't choke on missing Conditions" do
      response = Response.parse(fixture("noconditions_response.xml"))
      expect(response.assertions.first.conditions).to be_nil
    end

    describe "#validate" do
      let(:idp_entity) do
        idp_entity = Entity.new("issuer")
        idp = IdentityProvider.new
        idp.keys << KeyDescriptor.new(fixture("certificate.pem"))
        idp_entity.roles << idp

        idp_entity
      end

      before do
        sp.private_keys << OpenSSL::PKey::RSA.new(fixture("privatekey.key"))
      end

      it "succeeds" do
        response = Response.parse(fixture("response_signed.xml"))
        sp_entity.valid_response?(response, idp_entity, verification_time: Time.parse("2015-02-12T22:51:30Z"))
        expect(response.errors).to eq []
      end

      it "checks the issuer" do
        response = Response.parse(fixture("response_signed.xml"))
        idp_entity.entity_id = "someoneelse"
        sp_entity.valid_response?(response, idp_entity, verification_time: Time.parse("2015-02-12T22:51:30Z"))
        expect(response.errors).to eq [
          "received unexpected message from 'issuer'; expected it to be from 'someoneelse'"
        ]
      end

      it "complains about old message" do
        response = Response.parse(fixture("response_signed.xml"))
        sp_entity.valid_response?(response, idp_entity)
        expect(response.errors.length).to eq 1
        expect(response.errors.first).to match(/not_on_or_after .* is earlier than/)
      end

      it "complains about mismatched audience restriction" do
        response = Response.parse(fixture("response_signed.xml"))
        sp_entity.entity_id = "someoneelse"
        sp_entity.valid_response?(response, idp_entity, verification_time: Time.parse("2015-02-12T22:51:30Z"))
        expect(response.errors).to eq ["audience someoneelse not in allowed list of http://siteadmin.instructure.com/saml2"]
      end

      it "complains about no signature" do
        response = Response.parse(fixture("response_with_encrypted_assertion.xml"))
        sp_entity.valid_response?(response, idp_entity, verification_time: Time.parse("2015-02-12T22:51:30Z"))
        expect(response.errors).to eq ["neither response nor assertion were signed"]
      end

      it "complains if the signature has been tampered with" do
        response = Response.parse(fixture("response_tampered_signature.xml"))
        sp_entity.valid_response?(response, idp_entity, verification_time: Time.parse("2015-02-12T22:51:30Z"))
        expect(response.errors).to eq ["signature is invalid"]
      end

      it "complains if the trusted certificate isn't what signed the response" do
        idp_entity.identity_providers.first.keys.clear
        idp_entity.identity_providers.first.fingerprints << "afe71c28ef740bc87425be13a2263d37971da1f9"

        response = Response.parse(fixture("response_tampered_certificate.xml"))
        sp_entity.valid_response?(response,
                                  idp_entity,
                                  verification_time: Time.parse("2015-02-12T22:51:30Z"))
        expect(response.errors).to eq ["signature is invalid"]
      end

      it "complains when we don't have any trusted keys" do
        response = Response.parse(fixture("response_signed.xml"))
        idp_entity.identity_providers.first.keys.clear
        sp_entity.valid_response?(response, idp_entity, verification_time: Time.parse("2015-02-12T22:51:30Z"))
        expect(response.errors).to eq ["could not find certificate to validate message"]
      end

      it "complains about a valid signature we don't trust" do
        response = Response.parse(fixture("response_signed.xml"))
        idp_entity.identity_providers.first.keys.clear
        idp_entity.identity_providers.first.keys << KeyDescriptor.new(fixture("othercertificate.pem"))
        sp_entity.valid_response?(response, idp_entity, verification_time: Time.parse("2015-02-12T22:51:30Z"))
        expect(response.errors.length).to eq 1
        expect(response.errors.first).to eq("no trusted signing key found")
      end

      it "validates signature by fingerprint" do
        response = Response.parse(fixture("response_signed.xml"))
        idp_entity.identity_providers.first.keys.clear
        idp_entity.identity_providers.first.fingerprints <<
          "1c:37:7d:30:c1:83:18:ea:20:8b:dc:d5:35:b6:16:85:17:58:f7:c9"

        sp_entity.valid_response?(response, idp_entity, verification_time: Time.parse("2015-02-12T22:51:30Z"))
        expect(response.errors).to eq []
      end

      it "complains when we don't have any trusted fingerprints" do
        response = Response.parse(fixture("response_signed.xml"))
        idp_entity.identity_providers.first.keys.clear
        idp_entity.identity_providers.first.fingerprints <<
          "1c:37:7d:30:c1:83:18:ea:20:8b:dc:d5:35:b6:16:85:17:58:f7:ca"

        sp_entity.valid_response?(response, idp_entity, verification_time: Time.parse("2015-02-12T22:51:30Z"))
        expect(response.errors).to eq ["no trusted signing key found"]
      end

      it "protects against xml signature wrapping attacks targeting nameid" do
        response = Response.parse(fixture("xml_signature_wrapping_attack_response_nameid.xml"))
        idp_entity.identity_providers.first.keys.clear
        idp_entity.identity_providers.first.fingerprints << "afe71c28ef740bc87425be13a2263d37971da1f9"

        sp_entity.valid_response?(response, idp_entity, verification_time: Time.parse("2012-08-03T20:07:16Z"))
        expect(response.errors.length).to eq 1
        expect(response.errors.first.to_s).to eq(
          "5:0: ERROR: Element '{urn:oasis:names:tc:SAML:2.0:assertion}Assertion': " \
          "This element is not expected. Expected is one of ( {http://www.w3.org/2000/09/xmldsig#}Signature, " \
          "{urn:oasis:names:tc:SAML:2.0:protocol}Extensions, {urn:oasis:names:tc:SAML:2.0:protocol}Status )."
        )
      end

      it "protects against xml signature wrapping attacks targeting attributes" do
        response = Response.parse(fixture("xml_signature_wrapping_attack_response_attributes.xml"))
        idp_entity.identity_providers.first.keys.clear
        idp_entity.identity_providers.first.fingerprints << "afe71c28ef740bc87425be13a2263d37971da1f9"

        sp_entity.valid_response?(response, idp_entity, verification_time: Time.parse("2012-08-03T20:07:16Z"))
        expect(response.errors.length).to eq 1
        expect(response.errors.first.to_s).to eq(
          "30:0: ERROR: Element '{urn:oasis:names:tc:SAML:2.0:assertion}Subject': This element is not expected."
        )
      end

      it "protects against xml signature wrapping attacks with duplicate IDs" do
        response = Response.parse(fixture("xml_signature_wrapping_attack_duplicate_ids.xml"))
        idp_entity.identity_providers.first.keys.clear
        idp_entity.identity_providers.first.fingerprints << "7292914fc5bffa6f3fe1e43fd47c205395fecfa2"

        sp_entity.valid_response?(response, idp_entity, verification_time: Time.parse("2014-02-01T13:48:10.831Z"))
        expect(response.errors.length).to eq 1
        expect(response.errors.first.to_s).to eq(
          "1:0: ERROR: Element '{urn:oasis:names:tc:SAML:2.0:assertion}Assertion', attribute 'ID': " \
          "'pfx77d6c794-8295-f1c4-298e-c25ecae8046d' is not a valid value of the atomic type 'xs:ID'."
        )
      end

      it "protects against additional mis-signed assertions" do
        response = Response.parse(fixture("xml_missigned_assertion.xml"))
        idp_entity.identity_providers.first.keys.clear
        idp_entity.identity_providers.first.fingerprints << "c38e789fcfbbd4727bd8ff7fc365b44fc3596bda"

        sp_entity.valid_response?(response, idp_entity, verification_time: Time.parse("2015-02-27T19:12:52Z"))
        expect(response.errors.map(&:to_s)).to eq [
          "2:0: ERROR: Element '{http://www.w3.org/2000/09/xmldsig#}Signature': This element is not expected.",
          "43:0: ERROR: Element '{http://www.w3.org/2000/09/xmldsig#}Signature': This element is not expected."
        ]
      end

      it "doesn't break the signature by decrypting elements first" do
        response = Response.parse(fixture("response_with_signed_assertion_and_encrypted_subject.xml"))
        sp_entity.valid_response?(response, idp_entity, verification_time: Time.parse("2015-02-12T22:51:30Z"))
        expect(response.errors).to eq []
        expect(response.assertions.first.subject.name_id.id).to eq "jacob"
      end

      it "allows signatures that don't include KeyInfo, if we have a full cert" do
        response = Response.parse(fixture("response_without_keyinfo.xml"))
        sp_entity.entity_id = "http://unimelb-dev.instructure.com/saml2"
        idp_entity.entity_id = "https://authidm3tst.unimelb.edu.au:443/oam/fed"
        idp_entity.identity_providers.first.keys.clear
        idp_entity.identity_providers.first.keys << KeyDescriptor.new(<<~BASE64)
          MIIB/jCCAWegAwIBAgIBCjANBgkqhkiG9w0BAQQFADAkMSIwIAYDVQQDExlhZGRlcjEua
          XRzLnVuaW1lbGIuZWR1LmF1MB4XDTE3MDUyMjA2MzQzOFoXDTI3MDUyMDA2MzQzOFowJD
          EiMCAGA1UEAxMZYWRkZXIxLml0cy51bmltZWxiLmVkdS5hdTCBnzANBgkqhkiG9w0BAQE
          FAAOBjQAwgYkCgYEAjJgoa5bPS+Jukq2vNaMwZ39L3IhAg6oOytz+bgOhmF+o5zYARbFq
          C67faa/rMSkfQwYIpp/MdsC8XHtHeR6HCJjbuPkH/EooHiREOClTI0EKZvI2Xv/DqexxE
          egRPxXiwPUEPozGGT1yWtSwkQTvRvA9tMpZl3yLg1LhDOP6s6MCAwEAAaNAMD4wDAYDVR
          0TAQH/BAIwADAPBgNVHQ8BAf8EBQMDB9gAMB0GA1UdDgQWBBRukBh7J1okLMIfSRpzF5o
          puj0LizANBgkqhkiG9w0BAQQFAAOBgQB0zySVaypIGRksTwpmjaQhMvNrYWGvj74Rs1iu
          qOdsEQkpgk5dQKRFiAFEr+6b7WN4k+IAH5S++l1R0bUG6k9HFSn7uy7AD+qZcdoUm9a39
          brtH2kefs0D3bQfrwkqggAtWKwqfU4r7nAcdtVE+CT3cny5QU2/mJav9W9bzFPMXQ==
        BASE64

        sp_entity.valid_response?(response, idp_entity, verification_time: Time.parse("2019-04-16T00:56:03Z"))
        expect(response.errors).to eq []
        expect(response.assertions.first.subject.name_id.id).to eq "testuserint.sso@staff.oimtest.unimelb.edu.au"
      end

      it "finds signatures the sign the assertion, not inside the assertion" do
        response = Response.parse(fixture("response_assertion_signed_reffed_from_response.xml"))
        sp_entity.entity_id = "http://wscc.instructure.com/saml2"
        idp_entity.entity_id = "https://my.wscc.edu/idp"
        idp_entity.identity_providers.first.keys.clear
        idp_entity.identity_providers.first.fingerprints << "c4f473274116a3cbc295c3abf77c7ed1ade9b904"

        sp_entity.valid_response?(response, idp_entity, verification_time: response.issue_instant)
        expect(response.errors).to eq []
        expect(response.assertions.first.subject.name_id.id).to eq "narnold@wscc.edu"
        expect(response).not_to be_signed
        expect(response.assertions.first).to be_signed
      end
    end
  end
end
