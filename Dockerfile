FROM ruby:2.6

RUN apt-get update && \
	apt-get install -y --no-install-recommends libxmlsec1-dev && \
	rm -rf /var/lib/apt/lists/*

RUN mkdir /app
WORKDIR /app
COPY Gemfile saml2.gemspec /app/
COPY lib/saml2/version.rb /app/lib/saml2/

RUN bundle install -j 4

COPY . /app/
