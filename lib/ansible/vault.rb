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
  end
end
