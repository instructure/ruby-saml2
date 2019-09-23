Ruby SAML2 Library
==================

[![Build Status](https://travis-ci.org/instructure/ruby-saml2.png)](https://travis-ci.org/instructure/ruby-saml2)
[![Code Climate](https://codeclimate.com/github/instructure/ruby-saml2/badges/gpa.svg)](https://codeclimate.com/github/instructure/ruby-saml2)
[![Gem Version](https://fury-badge.herokuapp.com/rb/saml2.png)](http://badge.fury.io/rb/saml2)

About
-----

This library is for building a custom SAML 2.0 SP or IdP with minimal headache.
A simple example of a Rails controller that just passes on an already
authenticated user to a single SP:


```ruby
require 'saml2'

class SamlIdpController < ApplicationController
  def create
    authn_request, @relay_state = SAML2::Bindings::HTTPRedirect.decode(params[:SAMLRequest])
    unless authn_request.is_a?(SAML2::AuthnRequest) &&
      authn_request.valid_schema? &&
      authn_request.valid_interoperable_profile? &&
      authn_request.resolve(self.class.service_provider)

      flash[:error] = "Invalid login request"
      return redirect_to @current_user ? root_url : login_url
    end

    if @current_user
      response = SAML2::Response.respond_to(authn_request,
          NameID.new(self.class.entity_id),
          self.class.idp_name_id(@current_user, sp))
      response.sign(self.class.x509_certificate, self.class.private_key)

      @saml_response = Base64.encode64(response.to_xml)
      @saml_acs_url = authn_request.assertion_consumer_service.location
      render template: "saml2/http_post", layout: false
    else
      redirect_to login_url
    end
  end

  protected
  def self.idp_name_id(user)
    SAML2::NameID.new(user.uuid, SAML2::NameID::Format::PERSISTENT)
  end

  def self.saml_config
    @config ||= YAML.load(File.read('saml.yml'))
  end

  def self.service_provider
    @sp ||= SAML2::Entity.parse(File.read(saml_config[:service_provider])).roles.first
  end

  def self.entity_id
    saml_config[:entity_id]
  end

  def self.x509_certificate
    @cert ||= File.read(saml_config[:encryption][:certificate])
  end

  def self.private_key
    @key ||= File.read(saml_config[:encryption][:private_key])
  end

  def self.signature_algorithm
    saml_config[:encryption][:algorithm]
  end
end

```

An example of a basic SP (obtain idp_metadata.xml from your IdP; craft your own sp_metadata.xml):

```ruby
require 'saml2'

class SamlSpController < ApplicationController
  class << self
    def idp_metadata
      @idp_metadata ||= SAML2::Entity.parse(Rails.root.join('config/saml/idp_metadata.xml'))
    end

    def sp_metadata
      @sp_metadata ||= SAML2::Entity.parse(Rails.root.join('config/saml/sp_metadata.xml'))
    end
  end

  def new
    authn_request = self.class.sp_metadata.initiate_authn_request(self.class.idp_metadata)
    redirect_to SAML2::Bindings::HTTPRedirect.encode(authn_request)
  end

  def create
    response, _relay_state = SAML2::Bindings::HTTP_POST.decode(request.request_parameters)
    unless self.class.sp_metadata.valid_response?(response, self.class.idp_metadata)
      logger.error("Failed to validate SAML response: #{response.errors}")
      raise ActionController::RoutingError.new('Not Found')
    end

    reset_session
    session[:username] = response.assertions.first.subject.name_id.id
    logger.info("Logged in as #{session[:username]}")

    redirect_to root_url
  end

  def metadata
    render xml: self.class.sp_metadata.to_xml
  end
end
```

And then in your routes.rb:

```ruby
  get 'login' => 'saml_sp#new'
  post 'login' => 'saml_sp#create'
  get 'SAML2' => 'saml_sp#metadata'
```

Copyright
-----------

Copyright (c) 2015-present Instructure, Inc. See LICENSE for details.
