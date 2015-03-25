require_relative '../spec_helper'

module SAML2
  describe Conditions do
    it "empty should be valid" do
      Conditions.new.valid?.must_equal :valid
    end

    it "should be valid with unknown condition" do
      conditions = Conditions.new
      conditions << Conditions::Condition.new
      conditions.valid?.must_equal :indeterminate
    end

    it "should be valid with timestamps" do
      conditions = Conditions.new
      now = Time.now.utc
      conditions.not_before = now - 5
      conditions.not_on_or_after = now + 30
      conditions.valid?.must_equal :valid
    end

    it "should be invalid with out of range timestamps" do
      conditions = Conditions.new
      now = Time.now.utc
      conditions.not_before = now - 35
      conditions.not_on_or_after = now - 5
      conditions.valid?.must_equal :invalid
    end

    it "should allow passing now" do
      conditions = Conditions.new
      now = Time.now.utc
      conditions.not_before = now - 35
      conditions.not_on_or_after = now - 5
      conditions.valid?(now: now - 10).must_equal :valid
    end

    it "should be invalid before indeterminate" do
      conditions = Conditions.new
      now = Time.now.utc
      conditions.not_before = now + 5
      conditions << Conditions::Condition.new
      conditions.valid?.must_equal :invalid
    end

    it "should be invalid before indeterminate (actual conditions)" do
      conditions = Conditions.new
      conditions << Conditions::Condition.new
      conditions << Conditions::AudienceRestriction.new('audience')
      conditions.valid?.must_equal :invalid
    end

  end

  describe Conditions::AudienceRestriction do
    it "should be invalid" do
      Conditions::AudienceRestriction.new('expected').valid?(audience: 'actual').must_equal :invalid
    end

    it "should be valid" do
      Conditions::AudienceRestriction.new('expected').valid?(audience: 'expected').must_equal :valid
    end

    it "should be valid with an array" do
      Conditions::AudienceRestriction.new(['expected', 'actual']).valid?(audience: 'actual').must_equal :valid
    end
  end
end
