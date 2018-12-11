require 'spec_helper'
require 'tempfile'

module Ansible
  RSpec.describe Vault do
    describe '.encrypted?(path)' do
      it 'must return true when the file is in the ansible vault format' do
        expect(Ansible::Vault).to be_encrypted(fixture_path('empty.yml'))
      end

      it 'must return false when the file appears to be plaintext' do
        expect(Ansible::Vault).to_not be_encrypted(fixture_path('plaintext.yml'))
      end
    end

    describe '.read(path:, password:)' do
      it 'must return the contents of a file encrypted using ansible-vault' do
        content = Ansible::Vault.read(path: fixture_path('empty.yml'), password: 'ansible')
        expect(content).to eq "---\n"
      end

      it 'must return the plaintext of an unencrypted file' do
        content = Ansible::Vault.read(path: fixture_path('plaintext.yml'), password: 'nope')
        expect(content).to eq File.read(fixture_path('plaintext.yml'))
      end
    end

    describe '.write(path:, password:, plaintext:)' do
      let(:plaintext) { "this is my sekret, there are many like it...\n" }
      let(:password) { 'ansible' }
      let(:file) { Tempfile.new('ansible-vault', TMP_PATH.to_s) }

      after do
        file.close!
      end

      it 'must write out a file readable by ansible-vault', :ansible_vault do
        Ansible::Vault.write(
          path: file.path,
          password: password,
          plaintext: plaintext
        )
        ansible_vault_decrypt(path: file.path, password: password)
        contents = File.read(file.path)
        expect(contents).to eq plaintext
      end
    end

    describe '#initialize(path:, password:, plaintext: :none, **options)' do
      it 'must raise a helpful exception when the password is nil' do
        expect {
          Vault.new(
            path: fixture_path('blank.yml'),
            password: nil
          )
        }.to raise_error(Ansible::Vault::BlankPassword)
      end

      it 'must raise a helpful exception when the password is a whitespace only string' do
        expect {
          Vault.new(
            path: fixture_path('blank.yml'),
            password: ''
          )
        }.to raise_error(Ansible::Vault::BlankPassword)
      end

      it 'must allow a nil password when the allow_blank_password option is set' do
          Vault.new(
            path: fixture_path('blank.yml'),
            password: nil,
            allow_blank_password: true
          )
      end
    end

    describe '#inspect' do
      let(:vault) {
        Vault.new(path: fixture_path('blank.yml'), password: 'this-is-the-password')
      }

      it 'must include only the first 4 characters of the password followed by elipses' do
        expect(vault.inspect).to_not include 'this-is-the-password'
        expect(vault.inspect).to include 'this...'
      end
    end

    describe '.decrypt_text(text:, password:)' do
      let(:text) { 'exampletext' }
      let(:password) { 'examplepassword' }
      let(:fake_return) { Struct.new('FAKE') }

      it 'delegates to TextDecryptor.decrypt' do
        expect(
          Ansible::Vault::TextDecryptor
        ).to receive(:decrypt).once.with(text: text, password: password).and_return(fake_return)

        actual = described_class.decrypt_text(text: text, password: password)
        expect(actual).to eq(fake_return)
      end
    end

    describe '.parse_and_decrypt_yaml(text:, password:, whitelist_classes: [], whitelist_symbols: [], aliases: false)' do
      let(:text) { 'exampletext' }
      let(:password) { 'examplepassword' }
      let(:fake_return) { Struct.new('FAKE') }
      let(:whitelist_classes) { [Object] }
      let(:whitelist_symbols) { %i(example) }
      let(:aliases) { true }

      it 'delegates to KeyValueDecryptor.decrypt' do
        expect(
          Ansible::Vault::KeyValueDecryptor
        ).to receive(:decrypt)
          .once
          .with(
            text: text,
            password: password,
            whitelist_classes: whitelist_classes,
            whitelist_symbols: whitelist_symbols,
            aliases: aliases
          ).and_return(fake_return)

        actual = described_class.parse_and_decrypt_yaml(
          text: text,
          password: password,
          whitelist_classes: whitelist_classes,
          whitelist_symbols: whitelist_symbols,
          aliases: aliases
        )
        expect(actual).to eq(fake_return)
      end
    end
  end
end
