require "ansible/vault/version"

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
  end
end
