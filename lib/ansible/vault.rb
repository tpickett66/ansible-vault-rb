require 'ansible/vault/bin_ascii'
require 'ansible/vault/file_reader'
require 'ansible/vault/version'

module Ansible
  class Vault
    def self.read(path:, password:)
      new(path: path, password: password).plaintext
    end

    def initialize(path:, password:)
      @path = path
      @password = password
    end

    def inspect
      %Q{#<Ansible::Vault:#{"0x00%x" % (object_id << 1)} @path="#{@path}", @password="#{@password[0,4]}...">}
    end

    def plaintext
      file = FileReader.new(@path)
    end
  end
end
