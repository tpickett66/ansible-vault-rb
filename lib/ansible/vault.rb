require 'oroku_saki'

require 'ansible/vault/bin_ascii'
require 'ansible/vault/encryptor'
require 'ansible/vault/decryptor'
require 'ansible/vault/file_reader'
require 'ansible/vault/file_writer'
require 'ansible/vault/version'

module Ansible
  # The top level class for interacting with Vault files.
  class Vault
    # The standard header for Ansible's current vault format
    FILE_HEADER = "$ANSIBLE_VAULT;1.1;AES256".freeze

    # Indicate if the file at the supplied path appeard to be encrypted by
    # Ansible Vault
    #
    # @param path [String, Pathname]
    def self.encrypted?(path)
      FileReader.new(path.to_s).encrypted?
    end

    # Read and decrypt, if necessary, the contents of a vault
    #
    # If the file does not appear to be encrypted the file is simply read.
    #
    # @param path [String, Pathname] The path to the file to read
    # @param password [String] The password for the file
    # @return [String] The plaintext contents of the vault, this is marked for
    #   zeroing before the GC reaps the object. Any data extracted/parsed from
    #   this string should be similarly wiped from memory when no longer used.
    def self.read(path:, password:)
      new(path: path, password: password).read
    end

    # Encrypt plaintext using the supplied and write it to the specified location
    #
    # @param path [String, Pathname] The path to the file to write, truncated
    #   before writing
    # @param password [String] The password for the file
    # @param plaintext [String] The secrets to be protected
    # @return [File] The closed file handle the vault was written to
    def self.write(path:, password:, plaintext:)
      new(path: path, password: password, plaintext: plaintext).write
    end

    # Build a new Vault
    #
    # @param path [String, Pathname] The path to the file to read
    # @param password [String] The password for the file
    # @param plaintext [String] The plaintext of the file to be written when
    #   encrypting
    def initialize(path:, password:, plaintext: :none)
      @path = path.to_s
      @password = password.shred_later
      @plaintext = plaintext
      @plaintext.shred_later if String === @plaintext
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

    # Write the plaintext to the file specified
    #
    # @return [File] The closed file handle the vault was written to
    def write
      file = FileWriter.new(@path)
      encryptor = Encryptor.new(password: @password, file: file)
      encryptor.encrypt(@plaintext)
      file.write
    end

    # Extract the plaintext from a previously written vault file
    #
    # If the file does not appear to be encrypted the raw contents will be
    # returned.
    #
    # @return [String] The plaintext contents of the vault, this is marked for
    #   zeroing before the GC reaps the object. Any data extracted/parsed from
    #   this string should be similarly wiped from memory when no longer used.
    def read
      file = FileReader.new(@path)
      return File.read(@path) unless file.encrypted?
      decryptor = Decryptor.new(password: @password, file: file)
      decryptor.plaintext
    end
  end
end
