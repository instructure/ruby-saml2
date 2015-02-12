require_relative '../spec_helper'

module SAML2
  describe AssertionConsumerService::Array do
    it "should sort by index" do
      acses = AssertionConsumerService::Array.new(
          [AssertionConsumerService.new('b', 1),
           AssertionConsumerService.new('a', 0)])
      acses.map(&:location).must_equal ['a', 'b']
    end

    it "should be accessible by index" do
      acses = AssertionConsumerService::Array.new(
          [AssertionConsumerService.new('b', 3),
           AssertionConsumerService.new('a', 1)])
      acses.map(&:location).must_equal ['a', 'b']
      acses[1].location.must_equal 'a'
      acses[3].location.must_equal 'b'
      acses[0].must_equal nil
    end

    describe "#default" do
      it "should default to first entry if not otherwise specified" do
        acses = AssertionConsumerService::Array.new(
            [AssertionConsumerService.new('a', 0),
             AssertionConsumerService.new('b', 1)])
        acses.default.location.must_equal 'a'
      end

      it "should default to a tagged default" do
        acses = AssertionConsumerService::Array.new(
            [AssertionConsumerService.new('a', 0),
             AssertionConsumerService.new('b', 1, true)])
        acses.default.location.must_equal 'b'
      end
    end
  end
end
