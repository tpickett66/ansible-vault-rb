require 'ansible/vault/cryptor'

module Ansible
  class Vault
    # The class that handles decrypting an existing vault file
    class Decryptor < Cryptor
      # Decrypts the ciphertext from the file and strips any padding found.
      #
      # @return [String] The plaintext contents of the file, this is marked for
      #   zeroing before the GC reaps the object. Any data extracted/parsed
      #   from this string should be similarly wiped from memory when no longer
      #   used.
      def plaintext
        return @plaintext if defined?(@plaintext)
        unless hmac_matches?
          raise HMACMismatch, 'HMAC encoded in the file does not match calculated one!'
        end
        @plaintext = cipher(mode: :decrypt).update(file.ciphertext)
        padding_length = @plaintext[-1].codepoints.first
        @plaintext.sub!(/#{padding_length.chr}{#{padding_length}}\z/, '')
        @plaintext.shred_later
      end

      # Indicates if the HMAC present in the file matches the calculated one
      #
      # @return [Boolean]
      def hmac_matches?
        OrokuSaki.secure_compare(calculated_hmac, file.hmac)
      end

      private

      def salt
        file.salt
      end
    end
  end
end
