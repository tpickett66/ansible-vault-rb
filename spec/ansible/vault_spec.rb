require 'spec_helper'

module Ansible
  RSpec.describe Vault do
    describe '.open(path:, password:)' do
      it 'must return the contents of a file encrypted using ansible-vault' do
        pending "This top level example won't pass for a while."
        content = Ansible::Vault.read(path: fixture_path('empty.yml'), password: 'ansible')
        expect(content).to eq "---\n"
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
