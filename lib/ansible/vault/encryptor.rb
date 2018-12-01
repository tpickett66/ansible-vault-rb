require 'securerandom'

require 'ansible/vault/cryptor'
require 'ansible/vault/util'

module Ansible
  class Vault
    # The class that handles encrypting data to be written to a file.
    class Encryptor < Cryptor
      # Encrypt supplied plaintext, calculate HMAC, and pass to supplied {FileWriter}
      #
      # @param [String] plaintext The source data to be encrypted
      def encrypt(plaintext)
        padding_length = Util::BLOCK_SIZE - plaintext.bytesize % Util::BLOCK_SIZE
        padded_plaintext = (plaintext + (padding_length.chr * padding_length)).shred_later
        file.ciphertext = cipher(mode: :encrypt).update(padded_plaintext) + cipher.final
        file.salt = salt
        file.hmac = calculated_hmac
      end

      private

      def salt
        @salt ||= SecureRandom.random_bytes(Util::KEY_LENGTH)
      end
    end
  end
end
