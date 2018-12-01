require 'ansible/vault/util'

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
        decoded = Util.decode(body)
        return text unless Util.encrypted?(header, decoded[:hmac])
        keys    = Util.derive_keys(decoded[:salt], password)
        unless Util.hmac_matches?(keys[:hmac_key], decoded[:ciphertext], decoded[:hmac])
          raise HMACMismatch, 'HMAC encoded in the file does not match calculated one!'
        end
        Util.plaintext(decoded[:ciphertext], keys[:cipher_key], keys[:iv])
      end

      module_function :decrypt
    end
  end
end
