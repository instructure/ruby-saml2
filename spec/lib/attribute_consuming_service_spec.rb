require_relative '../spec_helper'

module SAML2
  describe AttributeConsumingService do
    describe "#create_statement" do
      let(:acs) do
        requested_attributes = [
            RequestedAttribute.new('name', true),
            RequestedAttribute.new('age')
        ]
        AttributeConsumingService.new('my service', requested_attributes)
      end

      it "should require name attribute" do
        -> { acs.create_statement({}) }.must_raise RequiredAttributeMissing
      end

      it "should create a statement" do
        stmt = acs.create_statement('name' => 'cody')
        stmt.attributes.length.must_equal 1
        stmt.attributes.first.name.must_equal 'name'
        stmt.attributes.first.value.must_equal 'cody'
      end

      it "should include optional attributes" do
        stmt = acs.create_statement('name' => 'cody', 'age' => 29)
        stmt.attributes.length.must_equal 2
        stmt.attributes.first.name.must_equal 'name'
        stmt.attributes.first.value.must_equal 'cody'
        stmt.attributes.last.name.must_equal 'age'
        stmt.attributes.last.value.must_equal 29
      end

      it "should ignore extra attributes" do
        stmt = acs.create_statement('name' => 'cody', 'height' => 73)
        stmt.attributes.length.must_equal 1
        stmt.attributes.first.name.must_equal 'name'
        stmt.attributes.first.value.must_equal 'cody'
      end

      it "should materialize deferred attributes" do
        stmt = acs.create_statement('name' => -> { 'cody' })
        stmt.attributes.length.must_equal 1
        stmt.attributes.first.name.must_equal 'name'
        stmt.attributes.first.value.must_equal 'cody'
      end

      it "should match explicit name formats" do
        acs.requested_attributes.first.name_format = 'format'
        stmt = acs.create_statement([Attribute.new('name', 'cody', nil, 'format'),
                                     Attribute.new('name', 'unspecified'),
                                     Attribute.new('name', 'other', nil, 'otherformat')])
        stmt.attributes.length.must_equal 1
        stmt.attributes.first.name.must_equal 'name'
        stmt.attributes.first.value.must_equal 'cody'
      end

      it "should match explicitly requested name formats" do
        acs.requested_attributes.first.name_format = 'format'
        stmt = acs.create_statement('name' => 'cody')
        stmt.attributes.length.must_equal 1
        stmt.attributes.first.name.must_equal 'name'
        stmt.attributes.first.value.must_equal 'cody'
      end

      it "should match explicitly provided name formats" do
        stmt = acs.create_statement([Attribute.new('name', 'cody', 'format')])
        stmt.attributes.length.must_equal 1
        stmt.attributes.first.name.must_equal 'name'
        stmt.attributes.first.value.must_equal 'cody'
      end
    end
  end
end
