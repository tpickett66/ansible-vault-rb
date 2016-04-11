require 'spec_helper'

module Ansible
  class Vault
    RSpec.describe Cryptor do
      it 'must not include the password in the output for #inspect' do
        cryptor = Cryptor.new(password: 'foo-bar-baz', file: instance_double(FileReader))
        expect(cryptor.inspect).to_not include 'foo-bar-baz'
      end
    end
  end
end
