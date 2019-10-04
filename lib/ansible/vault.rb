require 'oroku_saki'

require 'ansible/vault/bin_ascii'
require 'ansible/vault/encryptor'
require 'ansible/vault/decryptor'
require 'ansible/vault/text_decryptor'
require 'ansible/vault/key_value_decryptor'
require 'ansible/vault/file_reader'
require 'ansible/vault/file_writer'
require 'ansible/vault/version'

module Ansible
  # The top level class for interacting with Vault files.
  class Vault
    # The standard header for Ansible's current vault format
    FILE_HEADER = "$ANSIBLE_VAULT;1.1;AES256".freeze

    # Decrypt the ciphertext using specified password
    #
    # @param text [String] The encrypted text
    # @param password [String] The password for the text
    # @deprecated Use `Ansible::Vault.decrypt_text` instead.
    def self.decrypt(text:, password:)
      decrypt_text(text: text, password: password)
    end

    # Decrypt the ciphertext using specified password
    # @param text [String] The encrypted text
    # @param password [String] The password for the text
    def self.decrypt_text(text:, password:)
      TextDecryptor.decrypt(text: text, password: password)
    end

    # Parse and decrypt the YAML contents
    #
    # @param text [String] The YAML containing encrypted text
    # @param password [String] The password for the text
    # @param whitelist_classes [Array<Class>] classes to whitelist as safe to parse
    # @param whitelist_symbols [Array<Symbol>] symbols to whitelist as safe to parse
    # @param aliases [bool] whether to enable use of YAML aliases or not
    # @return [Object] The key(s) and plaintext contents of the ciphertext.
    def self.parse_and_decrypt_yaml(text:, password:, whitelist_classes: [], whitelist_symbols: [], aliases: false)
      KeyValueDecryptor.decrypt(
        text: text,
        password: password,
        whitelist_classes: whitelist_classes,
        whitelist_symbols: whitelist_symbols,
        aliases: aliases
      )
    end

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
    # @param password_file [String, Pathname] A password file for the file
    # @param options [Hash] Additional options, see {#initialize} for details
    # @return [String] The plaintext contents of the vault, this is marked for
    #   zeroing before the GC reaps the object. Any data extracted/parsed from
    #   this string should be similarly wiped from memory when no longer used.
    def self.read(path:, password: nil, password_file: nil, **options)
      new(path: path, password: password, password_file: password_file, **options).read
    end

    # Encrypt plaintext using the supplied and write it to the specified location
    #
    # @param path [String, Pathname] The path to the file to write, truncated
    #   before writing
    # @param password [String] The password for the file
    # @param password_file [String, Pathname] A password file for the file
    # @param plaintext [String] The secrets to be protected
    # @param options [Hash] Additional options, see {#initialize} for details
    # @return [File] The closed file handle the vault was written to
    def self.write(path:, password: nil, password_file: nil, plaintext:, **options)
      new(path: path, password: password, password_file: password_file, plaintext: plaintext, **options).write
    end

    # Build a new Vault
    #
    # @param path [String, Pathname] The path to the file to read
    # @param password [String] The password for the file
    # @param password_file [String, Pathname] A password file for the file    
    # @param options [Hash] Additional options
    # @param plaintext [String] The plaintext of the file to be written when
    #   encrypting
    # @option options [Boolean] :allow_blank_password Allow nil and empty string
    #   passwords, defaults to false.
    def initialize(path:, password: nil, password_file: nil, plaintext: :none, **options)
      @path = path.to_s
      @path = path
      @password = validate_password(password, password_file, options).shred_later
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

    private

    def validate_password(password, password_file, options)
      if !password.nil? && !password_file.nil?
        raise Error, "Password and password_file cannot both be defined."
      elsif !password_file.nil?
        password = IO.binread(password_file).strip
      end

      if !options[:allow_blank_password] && (password.nil? || password.strip.empty?)
        raise BlankPassword, 'A nil or empty string password was supplied!' \
          'If this is expected set the allow_blank_password option.'
      end
      password or ''
    end
  end
end
