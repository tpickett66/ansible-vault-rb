require 'yaml'
require 'ansible/vault/util'

module Ansible
  class Vault
    # KeyValueDecryptor that decrypts vault key-value pair(s) in YAML format.
    # Useful read to better understand the module: https://yaml.org/YAML_for_ruby.html
    module KeyValueDecryptor
      # AnsibleVaultHandler is a YAML handler,
      # equivalent of ansible/ansible's to handle `!vault` tags and decode them *when* needed.
      # It extends from `Psych::Handlers::DocumentStream` to handle multiple YAML documents
      # and retain all the functionality of `YAML.safe_load`.
      # Ref: https://github.com/ansible/ansible/blob/devel/lib/ansible/parsing/yaml/objects.py#L73
      class AnsibleVaultHandler < Psych::Handlers::DocumentStream
        VAULT_TAG = '!vault'

        def initialize(password, &block)
          super(&block)
          @password = password
        end

        def scalar(value, anchor, tag, plain, quoted, style)
          if tag == VAULT_TAG
            decrypted_value = Ansible::Vault::TextDecryptor.decrypt(
              text: value,
              password: @password
            )
            super(decrypted_value, anchor, tag, plain, quoted, style)
          else
            super(value, anchor, tag, plain, quoted, style)
          end
        end
      end

      # AnsibleVaultYamlLoader is a class that copies the `{YAML,Psych}` module
      # and adds support for ansible/ansible-vault decryption.
      # by providing the same interface for `.safe_load`.
      # It's meant to be used only internally by the `Ansible::Vault::KeyValueDecryptor` module.
      class AnsibleVaultYamlLoader
        # NOTE: Fixes `{YAML,Psych}`'s default `fallback` of `false`
        FALLBACK = nil

        def initialize(password)
          @password = password
        end

        # @param yaml [String] text content to parse
        # @param whitelist_classes [Array<Class>] classes to whitelist as safe to parse
        # @param whitelist_symbols [Array<Symbol>] symbols to whitelist as safe to parse
        # @param aliases [bool] whether to enable use of YAML aliases or not
        def safe_load(yaml, whitelist_classes = [], whitelist_symbols = [], aliases = false)
          document = parse(yaml)
          return {} if document.nil?

          class_loader = Psych::ClassLoader::Restricted.new(
            whitelist_classes.map(&:to_s),
            whitelist_symbols.map(&:to_s)
          )
          scanner = Psych::ScalarScanner.new(class_loader)
          visitor = if aliases
                      Psych::Visitors::ToRuby.new(scanner, class_loader)
                    else
                      Psych::Visitors::NoAliasRuby.new(scanner, class_loader)
                    end
          visitor.accept(document)
        end

        private

        def parse(yaml)
          parse_stream(yaml) do |node|
            return node
          end

          FALLBACK
        end

        def parse_stream(yaml, &block)
          @handler = KeyValueDecryptor::AnsibleVaultHandler.new(
            @password,
            &block
          )
          parser = Psych::Parser.new(
            @handler
          )
          parser.parse(yaml)
        end
      end

      # Decrypts the key-value pair(s)
      #
      # @param text [String] The encrypted text
      # @param password [String] The password for the text
      # @param whitelist_classes [Array<Class>] classes to whitelist as safe to parse
      # @param whitelist_symbols [Array<Symbol>] symbols to whitelist as safe to parse
      # @param aliases [bool] whether to enable use of YAML aliases or not
      # @return [Object] The key(s) and plaintext contents of the ciphertext.
      def self.decrypt(text:, password:, whitelist_classes: [], whitelist_symbols: [], aliases: false)
        loader = Ansible::Vault::KeyValueDecryptor::AnsibleVaultYamlLoader.new(password)
        result = loader.safe_load(text, whitelist_classes, whitelist_symbols, aliases)
        result || {}
      end
    end
  end
end
