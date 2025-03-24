# frozen_string_literal: true

module SAML2
  class Endpoint
    describe Array do
      context "with no endpoints" do
        let(:endpoints) { described_class.new }

        describe "#choose_binding" do
          it "returns nil" do
            expect(endpoints.choose_binding(Bindings::HTTP_POST::URN)).to be_nil
            expect(endpoints.choose_binding(Bindings::HTTPRedirect::URN, Bindings::HTTP_POST::URN)).to be_nil
            expect(endpoints.choose_binding("bogus")).to be_nil
          end
        end

        describe "#choose_endpoint" do
          it "returns nil" do
            expect(endpoints.choose_endpoint(Bindings::HTTP_POST::URN)).to be_nil
            expect(endpoints.choose_endpoint(Bindings::HTTPRedirect::URN)).to be_nil
            expect(endpoints.choose_endpoint("bogus")).to be_nil
          end
        end
      end

      context "with single endpoint with no binding defined" do
        let(:endpoints) { described_class.new([Endpoint.new("http://example.com", Bindings::HTTPRedirect::URN)]) }

        describe "#choose_binding" do
          it "returns the matching binding" do
            expect(endpoints.choose_binding(Bindings::HTTP_POST::URN, Bindings::HTTPRedirect::URN))
              .to eql Bindings::HTTPRedirect::URN
            expect(endpoints.choose_binding(Bindings::HTTPRedirect::URN, Bindings::HTTP_POST::URN))
              .to eql Bindings::HTTPRedirect::URN
            expect(endpoints.choose_binding("bogus")).to be_nil
          end
        end

        describe "#choose_endpoint" do
          it "returns the endpoint if the binding matches" do
            expect(endpoints.choose_endpoint(Bindings::HTTPRedirect::URN)).to be endpoints.first
          end

          it "returns nil if the binding does not match" do
            expect(endpoints.choose_endpoint(Bindings::HTTP_POST::URN)).to be_nil
          end
        end
      end

      context "with multiple endpoints with different bindings" do
        let(:endpoints) do
          described_class.new([
                                Endpoint.new("http://example.com/post", Bindings::HTTP_POST::URN),
                                Endpoint.new("http://example.com", Bindings::HTTPRedirect::URN)
                              ])
        end

        describe "#choose_binding" do
          it "returns the appropriate binding" do
            expect(endpoints.choose_binding(Bindings::HTTP_POST::URN)).to eql Bindings::HTTP_POST::URN
            expect(endpoints.choose_binding(Bindings::HTTPRedirect::URN)).to eql Bindings::HTTPRedirect::URN
            expect(endpoints.choose_binding(Bindings::HTTP_POST::URN, Bindings::HTTPRedirect::URN))
              .to eql Bindings::HTTP_POST::URN
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
            expect(endpoints.choose_endpoint(Bindings::HTTPRedirect::URN)).to be endpoints[1]
            expect(endpoints.choose_endpoint("bogus")).to be_nil
          end
        end
      end
    end
  end
end
