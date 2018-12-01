require 'openssl'

require 'ansible/vault/bin_ascii'

module Ansible
  class Vault
    # The module that decrypting an vault text
    module Util

      # The number of bytes in each key we need to generate
      KEY_LENGTH = 32
      # The number of bytes in the cipher's block
      BLOCK_SIZE = IV_LENGTH = 16
      # The number of iterations to use in the key derivation function, this
      # was pulled from the Ansible source. Do not change.
      KDF_ITERATIONS = 10_000
      # The total number of bytes to be output by the key derivation function.
      KDF_OUTPUT_LENGTH = (2 * KEY_LENGTH + IV_LENGTH)
      # The hashing algorithm for use in the KDF and HMAC calculations
      HASH_ALGORITHM = 'SHA256'.freeze
      # The Cipher spec OpenSSL expects when building our cipher object.
      CIPHER = 'AES-256-CTR'.freeze

      DIGEST = OpenSSL::Digest.new(HASH_ALGORITHM).freeze

      def derive_keys(salt, password)
        if salt.nil? || salt.strip.empty?
          raise MissingSalt, "Unable to derive keys, no salt available!"
        end
        key = OpenSSL::PKCS5.pbkdf2_hmac(
          password,
          salt,
          KDF_ITERATIONS,
          KDF_OUTPUT_LENGTH,
          HASH_ALGORITHM
        )
        ret = {
          cipher_key: key[0, KEY_LENGTH].shred_later,
          hmac_key: key[KEY_LENGTH, KEY_LENGTH].shred_later,
          iv: key[KEY_LENGTH*2, IV_LENGTH].shred_later,
        }
        key.shred!
        ret
      end

      def decode(text_line)
        temp_salt, hmac, temp_ciphertext = BinASCII.unhexlify(text_line).split("\n", 3)
        {
          salt: BinASCII.unhexlify(temp_salt),
          hmac: hmac,
          ciphertext: BinASCII.unhexlify(temp_ciphertext),
        }
      end

      def cipher(cipher_key, iv, mode: :decrypt)
        cipher ||= OpenSSL::Cipher.new(CIPHER).tap do |cipher|
          cipher.public_send(mode)
          cipher.key = cipher_key
          cipher.iv  = iv
        end
      end

      def calculate_hmac(hmac_key, ciphertext)
        hmac_algorithm = OpenSSL::HMAC.new(hmac_key, DIGEST)
        hmac_algorithm << ciphertext
        hmac_algorithm.hexdigest
      end

      def hmac_matches?(hmac_key, ciphertext, hmac)
        calculated_hmac = calculate_hmac(hmac_key, ciphertext)
        OrokuSaki.secure_compare(calculated_hmac, hmac)
      end

      def encrypted?(header, hmac)
        header == FILE_HEADER && !hmac.nil? && hmac.bytesize == 64
      end

      def plaintext(ciphertext, cipher_key, iv)
        text           = cipher(cipher_key, iv).update(ciphertext)
        padding_length = text[-1].codepoints.first
        text.sub!(/#{padding_length.chr}{#{padding_length}}\z/, '')
        text.shred_later
      end

      module_function :derive_keys, :decode, :cipher, :calculate_hmac,
        :hmac_matches?, :encrypted?, :plaintext
    end
  end
end
