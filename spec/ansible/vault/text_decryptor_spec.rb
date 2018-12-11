require 'spec_helper'
require 'ansible/vault/text_decryptor'

module Ansible
  class Vault
    RSpec.describe TextDecryptor do
      describe '.decrypt(text:, password:)' do
        context 'with encrypted text using ansible-vault' do
          let(:text) { File.read(fixture_path('empty.yml')) }

          it 'must return the decrypted contents' do
            content = described_class.decrypt(text: text, password: 'ansible')
            expect(content).to eq("---\n")
          end
        end

        context 'with plaintext' do
          let(:plaintext) { "this is my sekret, there are many like it...\n" }

          it 'must return the plaintext' do
            content = described_class.decrypt(text: plaintext, password: 'ansible')
            expect(content).to eq(plaintext)
          end
        end
      end
    end
  end
end
