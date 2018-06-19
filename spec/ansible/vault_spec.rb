require 'spec_helper'
require 'tempfile'

module Ansible
  RSpec.describe Vault do
    let(:password) { 'ansible' }    
    let(:password_file) { Tempfile.new('ansible-vault-password', TMP_PATH.to_s)
      .tap { |file| 
        file.write(password)
        file.rewind
      }
    }

    after do
      password_file.close!
    end

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
        content = Ansible::Vault.read(path: fixture_path('empty.yml'), password: password)
        expect(content).to eq "---\n"
      end
      
      it 'must return the contents of a file encrypted using ansible-vault with password_file' do
        content = Ansible::Vault.read(path: fixture_path('empty.yml'), password_file: password_file)
        expect(content).to eq "---\n"
      end

      it 'must return the plaintext of an unencrypted file' do
        content = Ansible::Vault.read(path: fixture_path('plaintext.yml'), password: 'nope')
        expect(content).to eq File.read(fixture_path('plaintext.yml'))
      end
    end

    describe '.write(path:, password:, plaintext:)' do
      let(:plaintext) { "this is my sekret, there are many like it...\n" }
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

      it 'must write out a file readable by ansible-vault with password_file', :ansible_vault do
        Ansible::Vault.write(
          path: file.path,
          password_file: password_file.path,
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

      it 'must raise an exception when both password and password_file are defined' do
        expect {
          Vault.new(
            path: fixture_path('blank.yml'),
            password: '',
            password_file: fixture_path('password.key')
          )
        }.to raise_error(Ansible::Vault::Error)
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
  end
end
