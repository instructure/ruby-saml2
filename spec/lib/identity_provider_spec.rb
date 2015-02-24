require_relative '../spec_helper'

module SAML2
  describe IdentityProvider do
    it "should serialize valid xml" do
      entity = Entity.new
      entity.entity_id = 'http://sso.canvaslms.com/SAML2'
      entity.organization = Organization.new('Canvas', 'Canvas by Instructure', 'https://www.canvaslms.com/')
      contact = Contact.new(Contact::Type::TECHNICAL)
      contact.company = 'Instructure'
      contact.email_addresses << 'mailto:ops@instructure.com'
      entity.contacts << contact

      idp = IdentityProvider.new
      idp.name_id_formats << NameID::Format::PERSISTENT
      idp.single_sign_on_services << Endpoint.new('https://sso.canvaslms.com/SAML2/Login')
      idp.keys << Key.new('somedata', Key::Type::SIGNING)

      entity.roles << idp
      Schemas.metadata.validate(Nokogiri::XML(entity.to_s)).must_equal []
    end
  end
end
