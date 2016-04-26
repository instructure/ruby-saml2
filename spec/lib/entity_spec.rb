require_relative '../spec_helper'

module SAML2
  describe Entity do
    it "should parse and validate" do
      entity = Entity.parse(fixture('service_provider.xml'))
      entity.valid_schema?.must_equal true
    end

    it "should return nil when not valid schema" do
      entity = Entity.parse("<xml></xml>")
      entity.must_equal nil
    end

    it "should return nil on non-XML" do
      entity = Entity.parse("garbage")
      entity.must_equal nil
    end

    describe "valid schema" do
      let(:entity) { Entity.parse(fixture('service_provider.xml')) }

      it "should find the id" do
        entity.entity_id.must_equal "http://siteadmin.instructure.com/saml2"
      end

      it "should parse the organization" do
        entity.organization.display_name.must_equal 'Canvas'
        entity.organization.display_name('en').must_equal 'Canvas'
        entity.organization.display_name('es').must_equal nil
        entity.organization.display_name(:all).must_equal en: 'Canvas'
      end

      it "validates metadata from ADFS containing lots of non-SAML schemas" do
        Entity.parse(fixture('FederationMetadata.xml')).valid_schema?.must_equal true
      end
    end

    describe Entity::Group do
      it "should parse and validate" do
        group = Entity.parse(fixture('entities.xml'))
        group.must_be_instance_of Entity::Group
        group.valid_schema?.must_equal true

        group.map(&:entity_id).must_equal ['urn:entity1', 'urn:entity2']
      end
    end
  end
end
