# frozen_string_literal: true

module SAML2
  class Endpoint
    class Indexed
      describe Array do
        context "with a later endpoint that's the default" do
          let(:endpoints) do
            described_class.new([
                                  Indexed.new("http://example.com/post", nil, nil, Bindings::HTTP_POST::URN),
                                  Indexed.new("http://example.com/redirect2",
                                              nil,
                                              false,
                                              Bindings::HTTPRedirect::URN),
                                  Indexed.new("http://example.com", nil, true, Bindings::HTTPRedirect::URN)
                                ])
          end

          describe "#choose_binding" do
            it "returns the appropriate binding" do
              expect(endpoints.choose_binding(Bindings::HTTP_POST::URN)).to eql Bindings::HTTP_POST::URN
              expect(endpoints.choose_binding(Bindings::HTTPRedirect::URN)).to eql Bindings::HTTPRedirect::URN
              expect(endpoints.choose_binding(Bindings::HTTP_POST::URN, Bindings::HTTPRedirect::URN))
                .to eql Bindings::HTTPRedirect::URN
              expect(endpoints.choose_binding(Bindings::HTTPRedirect::URN, Bindings::HTTP_POST::URN))
                .to eql Bindings::HTTPRedirect::URN
              expect(endpoints.choose_binding("bogus")).to be_nil
              expect(endpoints.choose_binding(Bindings::HTTPRedirect::URN, "bogus")).to eql Bindings::HTTPRedirect::URN
              expect(endpoints.choose_binding("bogus", Bindings::HTTP_POST::URN)).to eql Bindings::HTTP_POST::URN
            end
          end

          describe "#choose_endpoint" do
            it "returns the endpoint that matches the binding" do
              expect(endpoints.choose_endpoint(Bindings::HTTP_POST::URN)).to be endpoints[0]
              expect(endpoints.choose_endpoint(Bindings::HTTPRedirect::URN)).to be endpoints[2]
              expect(endpoints.choose_endpoint("bogus")).to be_nil
            end
          end
        end
      end
    end
  end
end
