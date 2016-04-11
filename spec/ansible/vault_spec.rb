require 'spec_helper'

module Ansible
  RSpec.describe Vault do
      let(:vault) {
        Vault.new(path: fixture_path('blank.yml'), password: 'ansible')
      }
    describe '.open(path:, password:)' do
      it 'must return the contents of a file encrypted using ansible-vault' do
        pending "This top level example won't pass for a while."
        content = Ansible::Vault.read(path: fixture_path('blank.yml'), password: 'ansible')
        expect(content).to eq "---\n"
      end
    end

  end
end
