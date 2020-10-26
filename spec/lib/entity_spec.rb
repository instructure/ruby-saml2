# frozen_string_literal: true

require_relative '../spec_helper'

module SAML2
  describe Entity do
    it "should parse and validate" do
      entity = Entity.parse(fixture('service_provider.xml'))
      expect(entity.valid_schema?).to eq true
    end

    it "should return nil when not valid schema" do
      entity = Entity.parse("<xml></xml>")
      expect(entity).to be_nil
    end

    it "should return nil on non-XML" do
      entity = Entity.parse("garbage")
      expect(entity).to be_nil
    end

    describe "valid schema" do
      let(:entity) { Entity.parse(fixture('service_provider.xml')) }

      it "should find the id" do
        expect(entity.entity_id).to eq "http://siteadmin.instructure.com/saml2"
      end

      it "should parse the organization" do
        expect(entity.organization.display_name.to_s).to eq 'Canvas'
        expect(entity.organization.display_name['en']).to eq 'Canvas'
        expect(entity.organization.display_name['es']).to be_nil
        expect(entity.organization.display_name[:all]).to eq en: 'Canvas'
      end

      it "validates metadata from ADFS containing lots of non-SAML schemas" do
        expect(Entity.parse(fixture('FederationMetadata.xml')).valid_schema?).to eq true
      end
    end

    it "should sign correctly" do
      entity = Entity.parse(fixture('service_provider.xml'))
      entity.sign(fixture('certificate.pem'), fixture('privatekey.key'))
      entity2 = Entity.parse(entity.to_s)
      expect(entity2.valid_schema?).to eq true
    end

    describe Entity::Group do
      it "should parse and validate" do
        group = Entity.parse(fixture('entities.xml'))
        expect(group).to be_instance_of(Entity::Group)
        expect(group.valid_schema?).to eq true

        expect(group.map(&:entity_id)).to eq ['urn:entity1', 'urn:entity2']
      end
    end
  end
end
