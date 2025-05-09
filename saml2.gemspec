# frozen_string_literal: true

$LOAD_PATH.push File.expand_path("lib", __dir__)
require "saml2/version"

Gem::Specification.new do |s|
  s.name = "saml2"
  s.version = SAML2::VERSION
  s.platform = Gem::Platform::RUBY
  s.authors = ["Cody Cutrer"]
  s.email = "cody@instructure.com'"
  s.homepage = "https://github.com/instructure/ruby-saml2"
  s.summary = "SAML 2.0 Library"
  s.description = <<~TEXT
    The saml2 library is yet another SAML library for Ruby, with
    an emphasis on _not_ re-implementing XML, especially XML Security,
    _not_ parsing via Regex or generating XML by string concatenation,
    _not_ serializing/re-parsing multiple times just to get it into
    the correct format to sign or validate.
  TEXT
  s.license = "MIT"
  s.bindir = "exe"
  s.executables = "bulk_verify_responses"
  s.files = Dir["{app,lib,schemas,exe}/**/*"] + ["Rakefile"]

  s.required_ruby_version = ">= 3.2"

  s.add_dependency "activesupport", ">= 3.2", "< 8.2"
  # Very specifically at least 1.5.8 - they fixed a bug with namespaces
  # on root elements with XML::Builder in that release
  s.add_dependency "nokogiri", ">= 1.5.8", "< 2.0"
  s.add_dependency "nokogiri-xmlsec-instructure", "~> 0.9", ">= 0.9.5"

  s.metadata["rubygems_mfa_required"] = "true"
end
