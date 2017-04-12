require_relative '../spec_helper'

module SAML2
  describe Conditions do
    it "empty should be valid" do
      expect(Conditions.new.valid?).to eq :valid
    end

    it "should be valid with unknown condition" do
      conditions = Conditions.new
      conditions << Conditions::Condition.new
      expect(conditions.valid?).to eq :indeterminate
    end

    it "should be valid with timestamps" do
      conditions = Conditions.new
      now = Time.now.utc
      conditions.not_before = now - 5
      conditions.not_on_or_after = now + 30
      expect(conditions.valid?).to eq :valid
    end

    it "should be invalid with out of range timestamps" do
      conditions = Conditions.new
      now = Time.now.utc
      conditions.not_before = now - 35
      conditions.not_on_or_after = now - 5
      expect(conditions.valid?).to eq :invalid
    end

    it "should allow passing now" do
      conditions = Conditions.new
      now = Time.now.utc
      conditions.not_before = now - 35
      conditions.not_on_or_after = now - 5
      expect(conditions.valid?(now: now - 10)).to eq :valid
    end

    it "should be invalid before indeterminate" do
      conditions = Conditions.new
      now = Time.now.utc
      conditions.not_before = now + 5
      conditions << Conditions::Condition.new
      expect(conditions.valid?).to eq :invalid
    end

    it "should be invalid before indeterminate (actual conditions)" do
      conditions = Conditions.new
      conditions << Conditions::Condition.new
      conditions << Conditions::AudienceRestriction.new('audience')
      expect(conditions.valid?).to eq :invalid
    end

  end

  describe Conditions::AudienceRestriction do
    it "should be invalid" do
      expect(Conditions::AudienceRestriction.new('expected').valid?(audience: 'actual')).to eq :invalid
    end

    it "should be valid" do
      expect(Conditions::AudienceRestriction.new('expected').valid?(audience: 'expected')).to eq :valid
    end

    it "should be valid with an array" do
      expect(Conditions::AudienceRestriction.new(['expected', 'actual']).valid?(audience: 'actual')).to eq :valid
    end
  end
end
