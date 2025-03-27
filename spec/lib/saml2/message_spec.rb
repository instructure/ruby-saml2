# frozen_string_literal: true

module SAML2
  describe Message do
    describe ".parse" do
      it "complains about invalid XML" do
        expect { Message.parse("garbage") }.to raise_error(CorruptMessage)
      end

      it "complains about getting the wrong type if calling on a subclass, and you get a different type" do
        expect { Response.parse(fixture("authnrequest.xml")) }.to raise_error(UnexpectedMessage)
      end
    end

    describe ".from_xml" do
      it "complains about unknown messages" do
        expect { Message.parse("<Garbage></Garbage>") }.to raise_error(UnknownMessage)
      end
    end

    describe "#issuer" do
      it "isn't required" do
        expect(Message.new.issuer).to be_nil
      end
    end
  end
end
