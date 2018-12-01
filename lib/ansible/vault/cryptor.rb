require 'openssl'

require 'ansible/vault/error'
require 'ansible/vault/util'

module Ansible
  class Vault
    # The base class for handling the en/decryption process
    #
    # This is here mostly to supply a consistent configuration for the various
    # primitives in use.
    #
    # @!attribute [r] file
    #   @return [FileReader] The object handling manipulating data for the vault
    #     format.
    class Cryptor
      attr_reader :file

      # Build a new cryptor object
      #
      # @param password [String] The password to be fed into the KDF
      # @param file [FileReader] The object for correctly reading/writing the
      #   Ansible vault file format.
      def initialize(password:, file:)
        @password = password
        @file = file
      end

      # Inspect the cryptor object.
      #
      # Overridden from the default to prevent key/password leakage.
      def inspect
        "#<#{self.class.name}:#{"0x00%x" % (object_id << 1)}>"
      end

      private

      def calculated_hmac
        return @calculated_hmac if defined?(@calculated_hmac)
        @calculated_hmac = Util.calculate_hmac(hmac_key, file.ciphertext)
      end

      def cipher(mode: :decrypt)
        @cipher ||= Util.cipher(cipher_key, iv)
      end

      def cipher_key
        return @cipher_key if defined?(@cipher_key)
        derive_keys
        @cipher_key
      end

      def hmac_key
        return @hmac_key if defined?(@hmac_key)
        derive_keys
        @hmac_key
      end

      def iv
        return @iv if defined?(@iv)
        derive_keys
        @iv
      end

      def derive_keys
        keys = Util.derive_keys(salt, @password)
        @cipher_key = keys[:cipher_key]
        @hmac_key = keys[:hmac_key]
        @iv = keys[:iv]
        nil
      end
    end
  end
end
