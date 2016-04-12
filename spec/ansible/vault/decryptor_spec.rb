require 'spec_helper'

module Ansible
  class Vault
    RSpec.describe Decryptor do
      describe '#hmac_matches?' do
        let(:file_reader) { FileReader.new(fixture_path('empty.yml')) }
        let(:decryptor) { Decryptor.new(file: file_reader, password: 'ansible') }

        it 'must return true when the caluclated value matches the file' do
          expect(decryptor.hmac_matches?).to eq true
        end

        it 'must return false when the hmac in the file is not the correct length' do
          allow(file_reader).to receive(:hmac).and_return('totes not correct')
          expect(decryptor.hmac_matches?).to eq false
        end

        it 'must return false when the hmac does not match' do
          hmac = file_reader.hmac
          hmac[-1] = 'd'
          allow(file_reader).to receive(:hmac).and_return(hmac)
          expect(decryptor.hmac_matches?).to eq false
        end
      end
    end
  end
end
