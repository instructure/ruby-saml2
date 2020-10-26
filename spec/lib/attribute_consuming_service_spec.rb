# frozen_string_literal: true

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
        expect { acs.create_statement({}) }.to raise_error RequiredAttributeMissing
      end

      it "should create a statement" do
        stmt = acs.create_statement('name' => 'cody')
        expect(stmt.attributes.length).to eq 1
        expect(stmt.attributes.first.name).to eq 'name'
        expect(stmt.attributes.first.value).to eq 'cody'
      end

      it "should include optional attributes" do
        stmt = acs.create_statement('name' => 'cody', 'age' => 29)
        expect(stmt.attributes.length).to eq 2
        expect(stmt.attributes.first.name).to eq 'name'
        expect(stmt.attributes.first.value).to eq 'cody'
        expect(stmt.attributes.last.name).to eq 'age'
        expect(stmt.attributes.last.value).to eq 29
      end

      it "should ignore extra attributes" do
        stmt = acs.create_statement('name' => 'cody', 'height' => 73)
        expect(stmt.attributes.length).to eq 1
        expect(stmt.attributes.first.name).to eq 'name'
        expect(stmt.attributes.first.value).to eq 'cody'
      end

      it "should materialize deferred attributes" do
        stmt = acs.create_statement('name' => -> { 'cody' })
        expect(stmt.attributes.length).to eq 1
        expect(stmt.attributes.first.name).to eq 'name'
        expect(stmt.attributes.first.value).to eq 'cody'
      end

      it "should match explicit name formats" do
        acs.requested_attributes.first.name_format = 'format'
        stmt = acs.create_statement([Attribute.new('name', 'cody', nil, 'format'),
                                     Attribute.new('name', 'unspecified'),
                                     Attribute.new('name', 'other', nil, 'otherformat')])
        expect(stmt.attributes.length).to eq 1
        expect(stmt.attributes.first.name).to eq 'name'
        expect(stmt.attributes.first.value).to eq 'cody'
      end

      it "should match explicitly requested name formats" do
        acs.requested_attributes.first.name_format = 'format'
        stmt = acs.create_statement('name' => 'cody')
        expect(stmt.attributes.length).to eq 1
        expect(stmt.attributes.first.name).to eq 'name'
        expect(stmt.attributes.first.value).to eq 'cody'
      end

      it "should match explicitly provided name formats" do
        stmt = acs.create_statement([Attribute.new('name', 'cody', 'format')])
        expect(stmt.attributes.length).to eq 1
        expect(stmt.attributes.first.name).to eq 'name'
        expect(stmt.attributes.first.value).to eq 'cody'
      end

      it "requires that provided attributes match a single default" do
        acs.requested_attributes.clear
        attr = RequestedAttribute.new('attr')
        attr.value = 'value'
        acs.requested_attributes << attr
        expect { acs.create_statement('attr' => 'something') }.to raise_error InvalidAttributeValue
        stmt = acs.create_statement('attr' => 'value')
        expect(stmt.attributes.length).to eq 1
        expect(stmt.attributes.first.name).to eq 'attr'
        expect(stmt.attributes.first.value).to eq 'value'
      end

      it "requires that provided attributes be from allowed enumeration" do
        acs.requested_attributes.clear
        attr = RequestedAttribute.new('attr')
        attr.value = ['value1', 'value2']
        acs.requested_attributes << attr
        expect { acs.create_statement('attr' => 'something') }.to raise_error InvalidAttributeValue
        stmt = acs.create_statement('attr' => 'value1')
        expect(stmt.attributes.length).to eq 1
        expect(stmt.attributes.first.name).to eq 'attr'
        expect(stmt.attributes.first.value).to eq 'value1'
      end

      it "auto-provides missing required attribute with a default" do
        acs.requested_attributes.clear
        attr = RequestedAttribute.new('attr', true)
        attr.value = 'value'
        acs.requested_attributes << attr
        stmt = acs.create_statement({})
        expect(stmt.attributes.length).to eq 1
        expect(stmt.attributes.first.name).to eq 'attr'
        expect(stmt.attributes.first.value).to eq 'value'
      end

      it "doesn't auto-provide missing required attribute with an enumeration" do
        acs.requested_attributes.clear
        attr = RequestedAttribute.new('attr', true)
        attr.value = ['value1', 'value2']
        acs.requested_attributes << attr
        expect { acs.create_statement({}) }.to raise_error RequiredAttributeMissing
      end

      it "doesn't auto-provide missing non-required attribute with a default" do
        acs.requested_attributes.clear
        attr = RequestedAttribute.new('attr')
        attr.value = 'value'
        acs.requested_attributes << attr
        stmt = acs.create_statement({})
        expect(stmt).to be_nil
      end

    end
  end
end
