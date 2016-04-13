module Ansible
  class Vault
    # A Ruby implementation of part of Python's binascii module
    module BinASCII
      # Convert the supplied binary string to the hex representation
      #
      # @param [String] bin_data The binary data to encode
      # @return [String] The hex encoded binary data.
      def self.hexlify(bin_data)
        bin_data.unpack('H*').first
      end

      # Convert the hexadecimal represenation of data back to binary
      #
      # @param [String] hex_data The hex data to convert back to binary
      # @return [String] The binary representation of the supplied hex data
      def self.unhexlify(hex_data)
        [hex_data].pack('H*')
      end
    end
  end
end
