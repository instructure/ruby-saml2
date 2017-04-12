require_relative '../../spec_helper'

module SAML2
  describe Bindings::HTTPRedirect do
    describe '.decode' do
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
        message = "\0" * 2 * 1024 * 1024
        allow(message).to receive(:destination).and_return("http://somewhere/")
        url = Bindings::HTTPRedirect.encode(message)

        expect { Bindings::HTTPRedirect.decode(url) }.to raise_error(MessageTooLarge)
      end

      it "complains about malformed deflated data" do
        check_error(CorruptMessage, Zlib::BufError) { Bindings::HTTPRedirect.decode("http://somewhere/?SAMLRequest=abcd") }
      end

      it "complains about zlibbed data" do
        # SAML uses just Deflate, which has no header/footer; Zlib adds a simple header/footer
        message = Base64.strict_encode64(Zlib::Deflate.deflate('abcd'))
        check_error(CorruptMessage, Zlib::DataError) { Bindings::HTTPRedirect.decode("http://somewhere/?SAMLRequest=#{message}") }
      end

      it "validates encoding" do
        message = "hi"
        allow(message).to receive(:destination).and_return("http://somewhere/")
        url = Bindings::HTTPRedirect.encode(message, relay_state: "abc")
        url << "&SAMLEncoding=garbage"
        expect { Bindings::HTTPRedirect.decode(url) }.to raise_error(UnsupportedEncoding)
      end

      it "returns relay state" do
        message = "hi"
        allow(message).to receive(:destination).and_return("http://somewhere/")
        url = Bindings::HTTPRedirect.encode(message, relay_state: "abc")
        allow(Message).to receive(:parse).with("hi").and_return("parsed")
        message, relay_state = Bindings::HTTPRedirect.decode(url)
        expect(message).to eq "parsed"
        expect(relay_state).to eq "abc"
      end
    end

    describe '.encode' do
      it 'works' do
        message = "hi"
        allow(message).to receive(:destination).and_return("http://somewhere/")
        url = Bindings::HTTPRedirect.encode(message, relay_state: "abc")
        expect(url).to match(%r{^http://somewhere/\?SAMLResponse=(?:.*)&RelayState=abc})
      end
    end
  end
end
