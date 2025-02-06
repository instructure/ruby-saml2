# frozen_string_literal: true

require "debug"
require "saml2"

def fixture(name)
  File.read(File.expand_path(File.join(__FILE__, "../fixtures", name)))
end
