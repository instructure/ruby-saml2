# frozen_string_literal: true

require_relative "../spec_helper"

module SAML2
  describe NameID do
    describe "#inspect" do
      it "returns just the id if that's the only present field" do
        expect(NameID.new("id").inspect).to eql '"id"'
      end

      it "returns the id and format if both are present" do
        expect(NameID.new("id", "format").inspect).to eql '"id"@"format"'
      end

      it "returns more common format if other fields are present" do
        expect(NameID.new("id", nil, name_qualifier: "name_qualifier").inspect).to eql(
          '#<SAML2::NameID id="id" name_qualifier="name_qualifier">'
        )
      end
    end
  end
end
