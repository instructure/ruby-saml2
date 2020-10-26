# frozen_string_literal: true

require_relative '../spec_helper'

module SAML2
  describe KeyInfo do
    describe '.format_fingerprint' do
      it 'strips non-hexadecimal characters' do
        expect(KeyInfo.format_fingerprint("\u200F abcdefghijklmnop 1234567890-\n a1")).to eq("ab:cd:ef:12:34:56:78:90:a1")
      end
    end
  end
end
