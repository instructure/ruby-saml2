require_relative '../spec_helper'

module SAML2
  describe IndexedObject::Array do
    it "should sort by index" do
      acses = Endpoint::Indexed::Array.new(
          [Endpoint::Indexed.new('b', 1),
           Endpoint::Indexed.new('a', 0)])
      acses.map(&:location).must_equal ['a', 'b']
    end

    it "should be accessible by index" do
      acses = Endpoint::Indexed::Array.new(
          [Endpoint::Indexed.new('b', 3),
           Endpoint::Indexed.new('a', 1)])
      acses.map(&:location).must_equal ['a', 'b']
      acses[1].location.must_equal 'a'
      acses[3].location.must_equal 'b'
      assert_nil(acses[0])
    end

    describe "#default" do
      it "should default to first entry if not otherwise specified" do
        acses = Endpoint::Indexed::Array.new(
            [Endpoint::Indexed.new('a', 0),
             Endpoint::Indexed.new('b', 1)])
        acses.default.location.must_equal 'a'
      end

      it "should default to a tagged default" do
        acses = Endpoint::Indexed::Array.new(
            [Endpoint::Indexed.new('a', 0),
             Endpoint::Indexed.new('b', 1, true)])
        acses.default.location.must_equal 'b'
      end
    end
  end
end
