require 'openssl'

require 'ansible/vault/error'

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

      # The number of bytes in each key we need to generate
      KEY_LENGTH = 32
      # The number of bytes in the IV needed for the cipher, a.k.a the
      # block length
      IV_LENGTH = 16
      # The number of iterations to use in the key derivation function, this
      # was pulled from the Ansible source. Do not change.
      KDF_ITERATIONS = 10_000
      # The total number of bytes to be output by the key derivation function.
      KDF_OUTPUT_LENGTH = (2 * KEY_LENGTH + IV_LENGTH)
      # The hashing algorithm for use in the KDF and HMAC calculations
      HASH_ALGORITHM = 'SHA256'.freeze
      # The Cipher spec OpenSSL expects when building our cipher object.
      CIPHER = 'AES-256-CTR'.freeze

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

      def cipher(mode: :decrypt)
        @cipher ||= OpenSSL::Cipher.new(CIPHER).tap do |cipher|
          cipher.public_send(mode)
          cipher.key = cipher_key
          cipher.iv = iv
        end
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
        if salt.nil? || salt.strip.empty?
          raise MissingSalt, "Unable to derive keys, no salt available!"
        end
        key = OpenSSL::PKCS5.pbkdf2_hmac(
          @password,
          salt,
          KDF_ITERATIONS,
          KDF_OUTPUT_LENGTH,
          HASH_ALGORITHM
        )
        @cipher_key = key[0,KEY_LENGTH].shred_later
        @hmac_key = key[KEY_LENGTH, KEY_LENGTH].shred_later
        @iv = key[KEY_LENGTH*2, IV_LENGTH].shred_later
        key.shred!
        nil
      end
    end
  end
end
