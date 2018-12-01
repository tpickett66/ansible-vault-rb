require 'ansible/vault/cryptor'
require 'ansible/vault/bin_ascii'

module Ansible
  class Vault
    # The module that decrypting an vault text
    module TextDecryptor
      # Decrypts the ciphertext
      #
      # @param text [String] The encrypted text
      # @param password [String] The password for the text
      # @return [String] The plaintext contents of the ciphertext.
      def decrypt(text:, password:)
        splited = text.split(/\R/)
        header  = splited.shift
        body    = splited.join()
        decoded = decode(body)
        return text unless encrypted?(header, decoded)
        keys    = derive_keys(decoded[:salt], password)
        digest  = OpenSSL::Digest.new(Cryptor::HASH_ALGORITHM)
        unless hmac_matches?(decoded, keys, digest)
          raise HMACMismatch, 'HMAC encoded in the file does not match calculated one!'
        end
        plaintext(decoded, keys, digest)
      end

      module_function :decrypt

      private
      def self.derive_keys(salt, password)
        if salt.nil? || salt.strip.empty?
          raise MissingSalt, "Unable to derive keys, no salt available!"
        end
        key = OpenSSL::PKCS5.pbkdf2_hmac(
          password,
          salt,
          Cryptor::KDF_ITERATIONS,
          Cryptor::KDF_OUTPUT_LENGTH,
          Cryptor::HASH_ALGORITHM
        )
        ret = {
          cipher_key: key[0, Cryptor::KEY_LENGTH].shred_later,
          hmac_key: key[Cryptor::KEY_LENGTH, Cryptor::KEY_LENGTH].shred_later,
          iv: key[Cryptor::KEY_LENGTH*2, Cryptor::IV_LENGTH].shred_later,
        }
        key.shred!
        ret
      end

      def self.decode(text_line)
        temp_salt, hmac, temp_ciphertext = BinASCII.unhexlify(text_line).split("\n", 3)
        {
          salt: BinASCII.unhexlify(temp_salt),
          hmac: hmac,
          ciphertext: BinASCII.unhexlify(temp_ciphertext),
        }
      end

      def self.cipher(decoded, keys, digest)
        cipher ||= OpenSSL::Cipher.new(Cryptor::CIPHER).tap do |cipher|
          cipher.public_send(:decrypt)
          cipher.key = keys[:cipher_key]
          cipher.iv  = keys[:iv]
        end
      end

      def self.hmac_matches?(decoded, keys, digest)
        hmac_algorithm = OpenSSL::HMAC.new(keys[:hmac_key], digest)
        hmac_algorithm << decoded[:ciphertext]
        OrokuSaki.secure_compare(hmac_algorithm.hexdigest, decoded[:hmac])
      end

      def self.encrypted?(header, decoded)
        header == FILE_HEADER && !decoded[:hmac].nil? && decoded[:hmac].bytesize == 64
      end

      def self.plaintext(decoded, keys, digest)
        text           = cipher(decoded, keys, digest).update(decoded[:ciphertext])
        padding_length = text[-1].codepoints.first
        text.sub!(/#{padding_length.chr}{#{padding_length}}\z/, '')
        text.shred_later
      end
    end
  end
end
