require 'spec_helper'

module Ansible
  class Vault
    RSpec.describe Decryptor do
      describe 'verify_hmac!' do
        let(:file_reader) { FileReader.new(fixture_path('empty.yml')) }
        let()
      end
    end
  end
end
