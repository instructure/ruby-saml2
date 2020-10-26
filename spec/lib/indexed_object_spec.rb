# frozen_string_literal: true

require_relative '../spec_helper'

module SAML2
  describe IndexedObject do
    describe "#default?" do
      it "always returns a boolean" do
        acs = Endpoint::Indexed.new('a', 0)
        expect(acs.default?).to eq false
        expect(acs.default_defined?).to eq false
      end

      it "#default_defined? works" do
        acs = Endpoint::Indexed.new('a', 0, false)
        expect(acs.default?).to eq false
        expect(acs.default_defined?).to eq true
      end
    end

    context "serialization" do
      it "doesn't include isDefault when it's nil" do
        acs = Endpoint::Indexed.new('a', 0)
        builder = double()
        expect(builder).to receive(:[]).and_return(builder).ordered
        expect(builder).to receive(:"AssertionConsumerService").ordered
        expect(builder).to receive(:parent).and_return(builder).ordered
        expect(builder).to receive(:children).and_return(builder).ordered
        expect(builder).to receive(:last).and_return(builder).ordered
        expect(builder).to receive(:[]=).with("index", 0).ordered

        acs.build(builder,"AssertionConsumerService")
      end
    end
  end

  describe IndexedObject::Array do
    it "should sort by index" do
      acses = Endpoint::Indexed::Array.new(
          [Endpoint::Indexed.new('b', 1),
           Endpoint::Indexed.new('a', 0)])
      expect(acses.map(&:location)).to eq ['a', 'b']
    end

    it "should be accessible by index" do
      acses = Endpoint::Indexed::Array.new(
          [Endpoint::Indexed.new('b', 3),
           Endpoint::Indexed.new('a', 1)])
      expect(acses.map(&:location)).to eq ['a', 'b']
      expect(acses[1].location).to eq 'a'
      expect(acses[3].location).to eq 'b'
      expect(acses[0]).to be_nil
    end

    describe "#default" do
      it "should default to first entry if not otherwise specified" do
        acses = Endpoint::Indexed::Array.new(
            [Endpoint::Indexed.new('a', 0),
             Endpoint::Indexed.new('b', 1)])
        expect(acses.default.location).to eq 'a'
      end

      it "should default to a tagged default" do
        acses = Endpoint::Indexed::Array.new(
            [Endpoint::Indexed.new('a', 0),
             Endpoint::Indexed.new('b', 1, true)])
        expect(acses.default.location).to eq 'b'
      end
    end
  end
end
