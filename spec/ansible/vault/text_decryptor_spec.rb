require 'spec_helper'
require 'ansible/vault/text_decryptor'

module Ansible
  class Vault
    RSpec.describe TextDecryptor do
      describe '.decrypt(text:, password:)' do
        let(:text) { File.read(fixture_path('empty.yml')) }
        let(:plaintext) { "this is my sekret, there are many like it...\n" }
        it 'must return the contents of text encrypted using ansible-vault' do
          content = TextDecryptor.decrypt(text: text, password: 'ansible')
          expect(content).to eq "---\n"
        end

        it 'must return the plaintext' do
          content = Vault.decrypt(text: plaintext, password: 'ansible')
          expect(content).to eq plaintext
        end
      end
    end
  end
end
