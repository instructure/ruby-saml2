# frozen_string_literal: true

module SAML2
  describe IndexedObject do
    describe "#default?" do
      it "always returns a boolean" do
        acs = Endpoint::Indexed.new("a", 0)
        expect(acs.default?).to be false
        expect(acs.default_defined?).to be false
      end

      it "#default_defined? works" do
        acs = Endpoint::Indexed.new("a", 0, false)
        expect(acs.default?).to be false
        expect(acs.default_defined?).to be true
      end
    end

    describe "#build" do
      it "doesn't include isDefault when it's nil" do
        acs = Endpoint::Indexed.new("a", 0)
        builder = double
        expect(builder).to receive(:[]).and_return(builder).ordered
        expect(builder).to receive(:AssertionConsumerService).ordered
        expect(builder).to receive(:parent).and_return(builder).ordered
        expect(builder).to receive(:children).and_return(builder).ordered
        expect(builder).to receive(:last).and_return(builder).ordered
        expect(builder).to receive(:[]=).with("index", 0).ordered

        acs.build(builder, "AssertionConsumerService")
      end
    end
  end
end
