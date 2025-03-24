# frozen_string_literal: true

module SAML2
  describe Conditions do
    it "empty should be valid" do
      expect(Conditions.new.valid?).to be true
    end

    it "should be invalid with unknown condition" do
      conditions = Conditions.new
      conditions << Conditions::Condition.new
      expect(conditions.valid?).to be false
    end

    it "should be valid with timestamps" do
      conditions = Conditions.new
      now = Time.now.utc
      conditions.not_before = now - 5
      conditions.not_on_or_after = now + 30
      expect(conditions.valid?).to be true
    end

    it "should be invalid with out of range timestamps" do
      conditions = Conditions.new
      now = Time.now.utc
      conditions.not_before = now - 35
      conditions.not_on_or_after = now - 5
      expect(conditions.valid?).to be false
    end

    it "should allow passing now" do
      conditions = Conditions.new
      now = Time.now.utc
      conditions.not_before = now - 35
      conditions.not_on_or_after = now - 5
      expect(conditions.valid?(now: now - 10)).to be true
    end

    it "should be invalid before indeterminate" do
      conditions = Conditions.new
      now = Time.now.utc
      conditions.not_before = now + 5
      conditions << Conditions::Condition.new
      expect(conditions.valid?).to be false
    end

    it "should be invalid before indeterminate (actual conditions)" do
      conditions = Conditions.new
      conditions << Conditions::Condition.new
      conditions << Conditions::AudienceRestriction.new("audience")
      expect(conditions.valid?).to be false
    end
  end
end
