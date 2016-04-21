module Ansible
  class Vault
    # A class for reading the data encoded in an Ansible vault file.
    #
    # @!attribute [r] body
    #   The encoded body of the file.
    # @!attribute [r] header
    #   The header of the file, not currently used.
    # @!attribute [r] path
    #   The path of the file being read.
    class FileReader
      attr_reader :body, :header, :path

      def initialize(path)
        @path = path
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

      # Indicates if the file is in the encrypted format or not
      #
      # @return [Boolean]
      def encrypted?
        decode_body unless defined?(@salt)
        # The header not matching is a dead giveaway that the file isn't what
        # we're expecting. That, however, probably isn't enough so we'll check
        # the HMAC for presence and length since it's very unlikely that
        # decoding the file body will result in multiple chunks AND the second
        # one being the correct length for a SHA256 HMAC.
        @header == FILE_HEADER && !@hmac.nil? && @hmac.bytesize == 64
      end

      private

      def decode_body
        salt, @hmac, ciphertext = BinASCII.unhexlify(@body).split("\n", 3)
        @ciphertext = BinASCII.unhexlify(ciphertext)
        @salt = BinASCII.unhexlify(salt)
      end
    end
  end
end
