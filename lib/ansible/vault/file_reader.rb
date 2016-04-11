module Ansible
  class Vault
    # A class for reading the data encoded in an Ansible vault file.
    #
    # @!attribute [r] body
    #   The encoded body of the file.
    # @!attribute [r] header
    #   The header of the file, not currently used.
    class FileReader
      attr_reader :body, :header

      def initialize(path)
        ::File.open(path, 'r') { |f|
          @header = f.gets.chomp
          @body = f.readlines.map(&:chomp).join
        }
      end

      # Extracts and decodes the ciphertext from the file body
      #
      # @return [String] The raw binary representation of the ciphertext
      def ciphertext
        return @ciphertext if defined?(@ciphertext)
        decode_body
        @ciphertext
      end

      # Extracts the HMAC value from the file body
      #
      # @return [String] The hex representation of the HMAC
      def hmac
        return @hmac if defined?(@hmac)
        decode_body
        @hmac
      end

      # Extracts and decodes the salt from the file body
      #
      # @return [String] The raw binary representation of the salt
      def salt
        return @salt if defined?(@salt)
        decode_body
        @salt
      end

      private

      def decode_body
        salt, @hmac, ciphertext = BinASCII.unhexlify(@body).split("\n")
        @ciphertext = BinASCII.unhexlify(ciphertext)
        @salt = BinASCII.unhexlify(salt)
      end
    end
  end
end
