require 'spec_helper'
require 'ansible/vault/bin_ascii'

module Ansible
  class Vault
    RSpec.describe BinASCII do
      describe '.unhexlify(data)' do
        it 'must match the python implementation', :python do
          data = '6465616462656566'
          expect(BinASCII.unhexlify(data)).to eq exec_python(%Q{from binascii import unhexlify; print(unhexlify("#{data}"))})
        end
      end
    end
  end
end
