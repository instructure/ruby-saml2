require_relative '../spec_helper'

module SAML2
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
