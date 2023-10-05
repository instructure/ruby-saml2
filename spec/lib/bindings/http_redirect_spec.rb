# frozen_string_literal: true

require_relative "../../spec_helper"

require "openssl"

module SAML2
  describe Bindings::HTTPRedirect do
    describe ".decode" do
      def check_error(wrapped, cause)
        error = nil
        begin
          yield
        rescue => e
          error = e
        end
        expect(error).not_to be_nil
        expect(error).to be_a(wrapped)
        expect(error.cause).to be_a(cause)
      end

      it "complains about invalid URIs" do
        check_error(CorruptMessage, URI::InvalidURIError) { Bindings::HTTPRedirect.decode(" ") }
      end

      it "complains about missing message" do
        expect { Bindings::HTTPRedirect.decode("http://somewhere/") }.to raise_error(MissingMessage)
        expect { Bindings::HTTPRedirect.decode("http://somewhere/?RelayState=bob") }.to raise_error(MissingMessage)
      end

      it "complains about malformed Base64" do
        check_error(CorruptMessage, ArgumentError) { Bindings::HTTPRedirect.decode("http://somewhere/?SAMLRequest=%^") }
      end

      it "doesn't allow deflate bombs" do
        message = double
        allow(message).to receive_messages(destination: "http://somewhere/", to_s: "\0" * 2 * 1024 * 1024)
        url = Bindings::HTTPRedirect.encode(message)

        expect { Bindings::HTTPRedirect.decode(url) }.to raise_error(MessageTooLarge)
      end

      it "complains about malformed deflated data" do
        check_error(CorruptMessage, Zlib::BufError) { Bindings::HTTPRedirect.decode("http://somewhere/?SAMLRequest=abcd") }
      end

      it "complains about zlibbed data" do
        # SAML uses just Deflate, which has no header/footer; Zlib adds a simple header/footer
        message = Base64.strict_encode64(Zlib::Deflate.deflate("abcd"))
        check_error(CorruptMessage, Zlib::DataError) { Bindings::HTTPRedirect.decode("http://somewhere/?SAMLRequest=#{message}") }
      end

      it "validates encoding" do
        message = double
        allow(message).to receive_messages(destination: "http://somewhere/", to_s: "hi")
        url = Bindings::HTTPRedirect.encode(message, relay_state: "abc")
        url << "&SAMLEncoding=garbage"
        expect { Bindings::HTTPRedirect.decode(url) }.to raise_error(UnsupportedEncoding)
      end

      it "returns relay state" do
        message = double
        allow(message).to receive_messages(destination: "http://somewhere/", to_s: "hi")
        url = Bindings::HTTPRedirect.encode(message, relay_state: "abc")
        allow(Message).to receive(:parse).with("hi").and_return("parsed")
        message, relay_state = Bindings::HTTPRedirect.decode(url)
        expect(message).to eq "parsed"
        expect(relay_state).to eq "abc"
      end

      describe "signature validation" do
        # taken from logs of another system. It's a good one to test because the Signature
        # has to be taken out of the middle, so you can't just use the whole query string
        let(:url) do
          "/login/saml/logout?SAMLResponse=fZLNasMwEIRfxehuy7KVOhaOobSXQHtpSg" \
            "%2b9FP2sE4EjGa9U2rev7JBDoOQmLTO7s5%2fUoTyPk3jxRx%2fDG%2bDkHUK2f9" \
            "6Rr%2fpBN4pXMtdcq5xXbJurbb3JN1JCZZpSqQ0n2QfMaL3bkaooSbZHjLB3GKQL" \
            "qVSyJi95zup3xgVvRdkWVdN%2bkuwZMFgnw%2bo8hTChoNR%2b%2fwbQp8Im%2fx" \
            "x1iDMU2p%2fp6I%2fW0SXockw5Sfa0xFxGxNkJL9GicPIMKIIWh8fXF5HSCH0Rie" \
            "hwAm0HCyYldNct3%2f2OaK3Yw8AkSKVqXrJqYIpVst4ao0xtymZbD21bbXja7ec8" \
            "OhQrr%2ftzp9kHr%2f1I%2bm7lMV%2bs900SEeaFB%2bkXHgmHNAMWVyZg4lqgSf" \
            "VtNSBNiDB09DKh7y7veAgyRLy9PXkD2YccI9xPgKtaHKJO7ZFktO%2fobVf632fp" \
            "%2fwA%3d&Signature=eZejccsvxyLEZvkNdL3shazIPyBIfRwk0Ny5INfrwzhE4" \
            "0N%2bH4neEo7xoHi2ncJ0LQG6A71oxviVkqPWXUaePuAt3fbxTf%2bLkWPiXo0D6" \
            "GVebSgPSZIMrsU%2fawfou68yX%2bI5dk8KtFiMOPCf5818oJvCdYjszN5o%2fU8" \
            "0UlJdjiDK%2bMF2rtzx6ZEXs04MoMDWKgouTZUFxNZP3KJeFQumLbK99ZfJVl8Wl" \
            "4XDTs1DKq7eBJc1IgyH13LELxhHgCZMpARrCX65gCYhjnJWhmyTU4YFzdcwKeulY" \
            "cP0eTbMEqRy9s1sEaOH%2fTx3I46Fl%2bv7j3GbRiRTwqF9%2bqjAKbJjpw%3d" \
            "%3d&SigAlg=http%3a%2f%2fwww.w3.org%2f2000%2f09%2fxmldsig%23rsa-sha1"
        end
        let(:certificate) do
          OpenSSL::X509::Certificate.new(Base64.decode64(<<~BASE64)).public_key
            MIIFnzCCBIegAwIBAgIQItX5wssh0ecd46K65PkSNDANBgkqhkiG9w0BAQsFADCBkDE
            LMAkGA1UEBhMCR0IxGzAZBgNVBAgTEkdyZWF0ZXIgTWFuY2hlc3RlcjEQMA4GA1UEBx
            MHU2FsZm9yZDEaMBgGA1UEChMRQ09NT0RPIENBIExpbWl0ZWQxNjA0BgNVBAMTLUNPT
            U9ETyBSU0EgRG9tYWluIFZhbGlkYXRpb24gU2VjdXJlIFNlcnZlciBDQTAeFw0xNjA5
            MDgwMDAwMDBaFw0xOTEwMjUyMzU5NTlaMIGeMSEwHwYDVQQLExhEb21haW4gQ29udHJ
            vbCBWYWxpZGF0ZWQxSTBHBgNVBAsTQElzc3VlZCB0aHJvdWdoIEl2eSBUZWNoIENvbW
            11bml0eSBDb2xsZWdlIG9mIEluZGlhbmEgRS1QS0kgTWFuYWcxEzARBgNVBAsTCkNPT
            U9ETyBTU0wxGTAXBgNVBAMTEGFkZnMuaXZ5dGVjaC5lZHUwggEiMA0GCSqGSIb3DQEB
            AQUAA4IBDwAwggEKAoIBAQC58zHz7VsV9S2XZMRjgqiWxBZ6M9y6/3zkrbObJ9hZqO7
            giCoonNDuELUiNt8pBqF8aHef8qbDOecBBXkz8rPAJL1S6lzvbxHIBuvEy+xOpVdUNM
            oyOaAYHOI5T6ueL1Q4iGMKfnWuXSvVTyB+9wAF/aWVFSoz+alUOiQtqTYyfgIKzHIAm
            FX7/SjFA9UjKVtqatcvzWsSWZHL4imeTmPosXXjmJVZnl+jaeFsnmW59o66sdGR+NYk
            hsBcVRnuP3MdxVgr5xSJMN+/BgZwCncX+4LJq5664eeQcJM5Km9kbQ/jMFhYy765ejs
            zcL0vWe/fS7tdXQCfoKjRZ5LzNEb3AgMBAAGjggHjMIIB3zAfBgNVHSMEGDAWgBSQr2
            o6lFoL2JDqElZz30O0Oija5zAdBgNVHQ4EFgQUdFr6SnHaXUqLAEdOL9qrTJS/3AYwD
            gYDVR0PAQH/BAQDAgWgMAwGA1UdEwEB/wQCMAAwHQYDVR0lBBYwFAYIKwYBBQUHAwEG
            CCsGAQUFBwMCME8GA1UdIARIMEYwOgYLKwYBBAGyMQECAgcwKzApBggrBgEFBQcCARY
            daHR0cHM6Ly9zZWN1cmUuY29tb2RvLmNvbS9DUFMwCAYGZ4EMAQIBMFQGA1UdHwRNME
            swSaBHoEWGQ2h0dHA6Ly9jcmwuY29tb2RvY2EuY29tL0NPTU9ET1JTQURvbWFpblZhb
            GlkYXRpb25TZWN1cmVTZXJ2ZXJDQS5jcmwwgYUGCCsGAQUFBwEBBHkwdzBPBggrBgEF
            BQcwAoZDaHR0cDovL2NydC5jb21vZG9jYS5jb20vQ09NT0RPUlNBRG9tYWluVmFsaWR
            hdGlvblNlY3VyZVNlcnZlckNBLmNydDAkBggrBgEFBQcwAYYYaHR0cDovL29jc3AuY2
            9tb2RvY2EuY29tMDEGA1UdEQQqMCiCEGFkZnMuaXZ5dGVjaC5lZHWCFHd3dy5hZGZzL
            ml2eXRlY2guZWR1MA0GCSqGSIb3DQEBCwUAA4IBAQA0dXP0leDcdrr/iKk4nDSCofll
            PAWE8LE3mD9Yb9K+/oVymxpqNIVJesDPLtf1HqWk6S6eafcYvfzl9aTMcvwEkL27g2l
            9UQuICkQgqSEY5qTsK//u/2S98JqXep2oRyvxo3UHX+3Ouc3i49hQ0v05Faoeap/ZT3
            JEsMV2Go9UKRJbYBG9Nqq/CDBuTgyopKJ7fvCtsGxwsvlUAz/NMuNoUphPQ2S+O/Sja
            bjR4XsAGU78Hji2tqJyvPyKPanxc0ioDdnL5lvrk4uZ/6Dy159C5FOFeLU2ZfiNLXRR
            85KFfhtX954qvX6jmM7CPmcidhzEnZV8fQv9G6XYPfrNL7bh
          BASE64
        end
        let(:incorrect_certificate) { OpenSSL::X509::Certificate.new(fixture("certificate.pem")).public_key }

        it "validates the signature" do
          # no exception raised
          Bindings::HTTPRedirect.decode(url, public_key: certificate)
        end

        it "raises on invalid signature" do
          expect do
            Bindings::HTTPRedirect.decode(url, public_key: incorrect_certificate)
          end.to raise_error(InvalidSignature)
        end

        it "raises on unsupported signature algorithm" do
          x = url.dup
          # SigAlg is now sha10
          x << "0"
          expect do
            Bindings::HTTPRedirect.decode(x, public_key: certificate)
          end.to raise_error(UnsupportedSignatureAlgorithm)
        end

        it "allows the caller to detect an unsigned message" do
          message = double
          allow(message).to receive_messages(destination: "http://somewhere/", to_s: "hi")
          url = Bindings::HTTPRedirect.encode(message)
          allow(Message).to receive(:parse).with("hi").and_return("parsed")

          expect do
            Bindings::HTTPRedirect.decode(url) do |_message, sig_alg|
              expect(sig_alg).to be_nil
              raise "no signature"
            end
          end.to raise_error("no signature")
        end

        it "requires a signature if a key is passed" do
          message = double
          allow(message).to receive_messages(destination: "http://somewhere/", to_s: "hi")
          url = Bindings::HTTPRedirect.encode(message)
          allow(Message).to receive(:parse).with("hi").and_return("parsed")

          expect { Bindings::HTTPRedirect.decode(url, public_key: certificate) }.to raise_error(UnsignedMessage)
        end

        it "notifies the caller which key was used" do
          called = 0
          key_used = lambda do |key|
            expect(key).to eq certificate
            called += 1
          end
          Bindings::HTTPRedirect.decode(url,
                                        public_key: [incorrect_certificate,
                                                     certificate],
                                        public_key_used: key_used)
          expect(called).to eq 1
        end
      end
    end

    describe ".encode" do
      it "works" do
        message = double
        allow(message).to receive_messages(destination: "http://somewhere/", to_s: "hi")
        url = Bindings::HTTPRedirect.encode(message, relay_state: "abc")
        expect(url).to match(%r{^http://somewhere/\?SAMLResponse=(?:.*)&RelayState=abc})
      end

      it "signs a message" do
        message = double
        allow(message).to receive_messages(destination: "http://somewhere/", to_s: "hi")
        key = OpenSSL::PKey::RSA.new(fixture("privatekey.key"))
        url = Bindings::HTTPRedirect.encode(message,
                                            relay_state: "abc",
                                            private_key: key)

        # verify the signature
        allow(Message).to receive(:parse).with("hi").and_return("parsed")
        Bindings::HTTPRedirect.decode(url) do |_message, sig_alg|
          expect(sig_alg).to eq Bindings::HTTPRedirect::SigAlgs::RSA_SHA1
          OpenSSL::X509::Certificate.new(fixture("certificate.pem")).public_key
        end
      end

      it "signs a message with RSA-SHA256" do
        message = double
        allow(message).to receive_messages(destination: "http://somewhere/", to_s: "hi")
        key = OpenSSL::PKey::RSA.new(fixture("privatekey.key"))
        url = Bindings::HTTPRedirect.encode(message,
                                            relay_state: "abc",
                                            private_key: key,
                                            sig_alg: Bindings::HTTPRedirect::SigAlgs::RSA_SHA256)

        # verify the signature
        allow(Message).to receive(:parse).with("hi").and_return("parsed")
        Bindings::HTTPRedirect.decode(url) do |_message, sig_alg|
          expect(sig_alg).to eq Bindings::HTTPRedirect::SigAlgs::RSA_SHA256
          OpenSSL::X509::Certificate.new(fixture("certificate.pem")).public_key
        end
      end
    end
  end
end
