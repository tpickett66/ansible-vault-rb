require 'ansible/vault/cryptor'

module Ansible
  class Vault
    # The class that handles decrypting an existing vault file
    class Decryptor < Cryptor
      # Decrypts the ciphertext from the file and strips any padding found.
      #
      # @return [String] The String contents of the file.
      def plaintext
        return @plaintext if defined?(@plaintext)
        verify_hmac!
        @plaintext = cipher(mode: :decrypt).update(file.ciphertext)
        padding_length = @plaintext[-1].codepoints.first
        @plaintext.sub!(/#{padding_length.chr}{#{padding_length}}\z/, '')
        @plaintext
      end

      # Verifies that the HMAC present in the file matches the one we calculate
      #
      # TODO: Short circuit on incorrect file hmac length
      # TODO: Run verification in constant time
      #
      # @return [TrueClass] True on success
      # @raise [HMACMismatch] When the calculated HMAC does not match the read one.
      def verify_hmac!
        if calculated_hmac == file.hmac
          true
        else
          raise HMACMismatch, 'HMAC encoded in the file does not match calculated one!'
        end
      end

      private

      def calculated_hmac
        return @calculated_hmac if defined?(@calculated_hmac)
        digest = OpenSSL::Digest.new(HASH_ALGORITHM)
        hmac_algorithm = OpenSSL::HMAC.new(hmac_key, digest)
        hmac_algorithm << file.ciphertext
        @calculated_hmac = hmac_algorithm.hexdigest
      end

      def salt
        file.salt
      end
    end
  end
end
