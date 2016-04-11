module Ansible
  class Vault
    # A Ruby implementation of part of Python's binascii module
    module BinASCII
      # Convert the hexadecimal represenation of data back to binary
      #
      # @param [String] The hex data to convert back to binary
      # @return [String] The binary representation of the supplied hex data
      def self.unhexlify(hex_data)
        [hex_data].pack('H*')
      end
    end
  end
end
