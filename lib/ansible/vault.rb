require 'ansible/vault/bin_ascii'
require 'ansible/vault/decryptor'
require 'ansible/vault/file_reader'
require 'ansible/vault/version'

module Ansible
  # The top level class for interacting with Vault files.
  class Vault
    # Read and decrypt the plaintext contents of a vault
    #
    # @param path [String] The path to the file to read
    # @param password [String] The password for the file
    # @return [String] The plaintext contents of the vault, this is marked for
    #   zeroing before the GC reaps the object. Any data extracted/parsed from
    #   this string should be similarly wiped from memory when no longer used.
    def self.read(path:, password:)
      new(path: path, password: password).plaintext
    end

    # Build a new Vault
    #
    # @param path [String] The path to the file to read
    # @param password [String] The password for the file
    def initialize(path:, password:)
      @path = path
      @password = password.shred_later
    end

    # Inspect this vault
    #
    # Overridden from the default implementation to prevent passwords from
    # being leaked into logs.
    #
    # @return [String]
    def inspect
      %Q{#<Ansible::Vault:#{"0x00%x" % (object_id << 1)} @path="#{@path}", @password="#{@password[0,4]}...">}
    end

    # Extract the plaintext from a previously written vault file
    #
    # @return [String] The plaintext contents of the vault, this is marked for
    #   zeroing before the GC reaps the object. Any data extracted/parsed from
    #   this string should be similarly wiped from memory when no longer used.
    def plaintext
      file = FileReader.new(@path)
      decryptor = Decryptor.new(password: @password, file: file)
      decryptor.plaintext
    end
  end
end
