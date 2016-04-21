module Ansible
  class Vault
    class Error < StandardError; end
    class MissingSalt < Error; end
    class HMACMismatch < Error; end
    class BlankPassword < Error; end
  end
end
