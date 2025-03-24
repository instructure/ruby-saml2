# frozen_string_literal: true

module SAML2
  class Conditions
    describe AudienceRestriction do
      it "should be invalid" do
        expect(AudienceRestriction.new("expected").valid?(audience: "actual")).to be false
      end

      it "should be valid" do
        expect(AudienceRestriction.new("expected").valid?(audience: "expected")).to be true
      end

      it "should be valid with an array" do
        expect(AudienceRestriction.new(%w[expected actual]).valid?(audience: "actual")).to be true
      end

      it "is valid when ignored" do
        expect(AudienceRestriction.new("expected").valid?(audience: "actual",
                                                          ignore_audience_condition: true)).to be true
      end
    end
  end
end
