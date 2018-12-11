require 'spec_helper'
require 'ansible/vault/key_value_decryptor'

module Ansible
  class Vault
    RSpec.describe KeyValueDecryptor do
      describe '.decrypt(text:, password:, whitelist_classes: [], whitelist_symbols: [], aliases: false)' do
        context 'with present `text`' do
          # NOTE: Skip testing all the possible variants with `aliases` and all other args,
          # since `aliases` are toggles whether to enable YAML aliases or not.
          context 'and `aliases` that is `true`' do
            context 'and YAML document containing aliases' do
              let(:text) do
                File.read(
                  fixture_path(
                    File.join('key_value_decryptor/aliases.yml')
                  )
                )
              end
              let(:expected) do
                %w[Steve Clark Brian Oren Steve]
              end
              it 'must return the content with the aliases' do
                content = described_class.decrypt(text: text, password: 'ansible', aliases: true)
                expect(content).to eq(expected)
              end
            end

            context 'and YAML document not containing aliases' do
              let(:text) do
                File.read(
                  fixture_path('plaintext.yml')
                )
              end
              let(:expected) do
                {
                  "key" => "value",
                  "foo" => "bar",
                  "baz" => {
                    "qux" => [42]
                  }
                }
              end
              it 'must return the content as it is' do
                content = described_class.decrypt(text: text, password: 'ansible', aliases: true)
                expect(content).to eq(expected)
              end
            end
          end

          context 'and `aliases` that is `false`' do
            context 'and YAML document containing aliases' do
              let(:text) do
                File.read(
                  fixture_path(
                    File.join('key_value_decryptor/aliases.yml')
                  )
                )
              end
              let(:expected) do
                %w[Steve Clark Brian Oren Steve]
              end
              it 'must raise Psych::BadAlias' do
                expect do
                  described_class.decrypt(text: text, password: 'ansible', aliases: false)
                end.to raise_error(Psych::BadAlias)
              end
            end

            context 'and YAML document not containing aliases' do
              let(:text) do
                File.read(
                  fixture_path('plaintext.yml')
                )
              end
              let(:expected) do
                {
                  "key" => "value",
                  "foo" => "bar",
                  "baz" => {
                    "qux" => [42]
                  }
                }
              end
              it 'must return the content as it is' do
                content = described_class.decrypt(text: text, password: 'ansible', aliases: true)
                expect(content).to eq(expected)
              end
            end
          end

          # NOTE: Skip testing all the possible variants with `whitelist_symbols` and all other args,
          # since `whitelist_symbols` are toggles whether to enable YAML symbols or not.
          context 'and `whitelist_classes` include `Symbol` and `whitelist_symbols` that are present' do
            context 'and with YAML document containing symbols' do
              context 'and symbols are whitelisted' do
                let(:text) do
                  File.read(
                    fixture_path(
                      File.join('key_value_decryptor/symbols.yml')
                    )
                  )
                end
                let(:expected) do
                  {
                    "simple_symbol" => :Simple
                  }
                end
                it 'must return the content with the symbols' do
                  content = described_class.decrypt(
                    text: text,
                    password: 'ansible',
                    whitelist_classes: [Symbol],
                    whitelist_symbols: %i(Simple),
                    )
                  expect(content).to eq(expected)
                end
              end

              context 'and symbols are not whitelisted' do
                let(:text) do
                  File.read(
                    fixture_path(
                      File.join('key_value_decryptor/symbols.yml')
                    )
                  )
                end
                let(:expected) do
                  {
                    "simple_symbol" => :Simple
                  }
                end

                # NOTE: This seems like bad Ruby behavior, but it's consistent
                it 'must raise an error, but instead returns the content' do
                  content = described_class.decrypt(
                    text: text,
                    password: 'ansible',
                    whitelist_classes: [Symbol],
                    whitelist_symbols: []
                  )
                  expect(content).to eq(expected)
                end
              end
            end

            context 'and with YAML document not containing symbols' do
              let(:text) do
                File.read(
                  fixture_path('plaintext.yml')
                )
              end
              let(:expected) do
                {
                  "key" => "value",
                  "foo" => "bar",
                  "baz" => {
                    "qux" => [42]
                  }
                }
              end
              it 'must return the content as it is' do
                content = described_class.decrypt(
                  text: text,
                  password: 'ansible',
                  whitelist_classes: [Symbol],
                  whitelist_symbols: []
                )
                expect(content).to eq(expected)
              end
            end
          end

          context 'and `whitelist_classes` does not include `Symbol` and `whitelist_symbols` are empty' do
            context 'and with YAML document containing symbols' do
              let(:text) do
                File.read(
                  fixture_path(
                    File.join('key_value_decryptor/symbols.yml')
                  )
                )
              end
              let(:expected) do
                {
                  "simple_symbol" => :Simple
                }
              end
              it 'must raise Psych::DisallowedClass' do
                expect do
                  described_class.decrypt(
                    text: text,
                    password: 'ansible'
                  )
                end.to raise_error(Psych::DisallowedClass, 'Tried to load unspecified class: Symbol')
              end
            end
          end

          # NOTE: Skip testing all the possible variants with `whitelist_classes` and all other args,
          # since `whitelist_classes` are toggles whether to enable "dangerous" serialization types or not.
          context 'and `whitelist_classes` that are present' do
            context 'and YAML document containing whitelisted classes' do
              let(:text) do
                File.read(
                  fixture_path(
                    File.join('key_value_decryptor/whitelist_classes.yml')
                  )
                )
              end
              let(:expected) do
                {
                  "canonical" => Time.new(2018, 12, 11, 1, 2, 3, 0)
                }
              end
              it 'must return contents' do
                content = described_class.decrypt(
                  text: text,
                  password: 'ansible',
                  whitelist_classes: [Time]
                )

                expect(content).to eq(expected)
              end
            end

            context 'and YAML document containing standard/safe classes' do
              let(:text) do
                File.read(
                  fixture_path('plaintext.yml')
                )
              end
              let(:expected) do
                {
                  "key" => "value",
                  "foo" => "bar",
                  "baz" => {
                    "qux" => [42]
                  }
                }
              end
              it 'must return the content as it is' do
                content = described_class.decrypt(text: text, password: 'ansible', whitelist_classes: [])
                expect(content).to eq(expected)
              end
            end
          end

          context 'and `whitelist_classes` that are not present' do
            context 'and YAML document containing non-whitelisted classes' do
              let(:text) do
                File.read(
                  fixture_path(
                    File.join('key_value_decryptor/whitelist_classes.yml')
                  )
                )
              end
              let(:expected) do
                {
                  "canonical" => Time.new(2018, 12, 11, 1, 2, 3, 0)
                }
              end
              it 'must return contents' do
                expect do
                  described_class.decrypt(
                    text: text,
                    password: 'ansible',
                    whitelist_classes: []
                  )
                end.to raise_error(Psych::DisallowedClass, 'Tried to load unspecified class: Time')
              end
            end

            context 'and YAML document containing standard/safe classes' do
              let(:text) do
                File.read(
                  fixture_path('plaintext.yml')
                )
              end
              let(:expected) do
                {
                  "key" => "value",
                  "foo" => "bar",
                  "baz" => {
                    "qux" => [42]
                  }
                }
              end
              it 'must return the content as it is' do
                content = described_class.decrypt(text: text, password: 'ansible', whitelist_classes: [])
                expect(content).to eq(expected)
              end
            end
          end

          context 'and `text` is YAML with scalar node' do
            context 'and containing only a single key' do
              context 'and plaintext value' do
                let(:text) do
                  File.read(
                    fixture_path(
                      File.join('key_value_decryptor/scalar/plaintext_key.yml')
                    )
                  )
                end
                let(:expected) do
                  {
                    "key" => 'f'
                  }
                end
                it 'must return the contents of plaintext' do
                  content = described_class.decrypt(text: text, password: 'ansible')
                  expect(content).to eq(expected)
                end
              end

              context 'and encrypted value' do
                let(:text) do
                  File.read(
                    fixture_path(
                      File.join('key_value_decryptor/scalar/encrypted_key.yml')
                    )
                  )
                end
                let(:expected) do
                  {
                    "key" => 'f'
                  }
                end
                it 'must return the contents of text encrypted using ansible-vault' do
                  content = described_class.decrypt(text: text, password: 'ansible')
                  expect(content).to eq(expected)
                end
              end
            end
            context 'and containing multiple keys' do
              context 'and all are plaintext' do
                let(:text) do
                  File.read(
                    fixture_path(
                      File.join('key_value_decryptor/scalar/plaintext_keys.yml')
                    )
                  )
                end
                let(:expected) do
                  {
                    "key" => 'f',
                    "another_key" => 'f'
                  }
                end
                it 'must return the contents of plaintext' do
                  content = described_class.decrypt(text: text, password: 'ansible')
                  expect(content).to eq(expected)
                end
              end
              context 'and all are encrypted' do
                let(:text) do
                  File.read(
                    fixture_path(
                      File.join('key_value_decryptor/scalar/encrypted_keys.yml')
                    )
                  )
                end
                let(:expected) do
                  {
                    "key" => 'f',
                    "another_key" => 'f'
                  }
                end
                it 'must return the contents of text encrypted using ansible-vault' do
                  content = described_class.decrypt(text: text, password: 'ansible')
                  expect(content).to eq(expected)
                end
              end
              context 'and some are encrypted, others are plaintext' do
                let(:text) do
                  File.read(
                    fixture_path(
                      File.join('key_value_decryptor/scalar/encrypted_and_plaintext_keys.yml')
                    )
                  )
                end
                let(:expected) do
                  {
                    "key" => 'f',
                    "another_key" => 'f'
                  }
                end
                it 'must return the contents of text encrypted using ansible-vault and also plaintext' do
                  content = described_class.decrypt(text: text, password: 'ansible')
                  expect(content).to eq(expected)
                end
              end
            end
          end

          context 'and `text` is YAML with mapping node' do
            context 'and containing only a single key' do
              context 'and plaintext value' do
                let(:text) do
                  File.read(
                    fixture_path(
                      File.join('key_value_decryptor/mapping/plaintext_key.yml')
                    )
                  )
                end
                let(:expected) do
                  {
                    "my_mapping" => {
                      "key" => 'f'
                    }
                  }
                end
                it 'must return the contents of plaintext' do
                  content = described_class.decrypt(text: text, password: 'ansible')
                  expect(content).to eq(expected)
                end
              end

              context 'and encrypted value' do
                let(:text) do
                  File.read(
                    fixture_path(
                      File.join('key_value_decryptor/mapping/encrypted_key.yml')
                    )
                  )
                end
                let(:expected) do
                  {
                    "my_mapping" => {
                      "key" => 'f'
                    }
                  }
                end
                it 'must return the contents of text encrypted using ansible-vault' do
                  content = described_class.decrypt(text: text, password: 'ansible')
                  expect(content).to eq(expected)
                end
              end
            end
            context 'and containing multiple keys' do
              context 'and all are plaintext' do
                let(:text) do
                  File.read(
                    fixture_path(
                      File.join('key_value_decryptor/mapping/plaintext_keys.yml')
                    )
                  )
                end
                let(:expected) do
                  {
                    "my_mapping" => {
                      "key" => 'f',
                      "another_key" => 'f'
                    }
                  }
                end
                it 'must return the contents of plaintext' do
                  content = described_class.decrypt(text: text, password: 'ansible')
                  expect(content).to eq(expected)
                end
              end
              context 'and all are encrypted' do
                let(:text) do
                  File.read(
                    fixture_path(
                      File.join('key_value_decryptor/mapping/encrypted_keys.yml')
                    )
                  )
                end
                let(:expected) do
                  {
                    "my_mapping" => {
                      "key" => 'f',
                      "another_key" => 'f'
                    }
                  }
                end
                it 'must return the contents of text encrypted using ansible-vault' do
                  content = described_class.decrypt(text: text, password: 'ansible')
                  expect(content).to eq(expected)
                end
              end
              context 'and some are encrypted, others are plaintext' do
                let(:text) do
                  File.read(
                    fixture_path(
                      File.join('key_value_decryptor/mapping/encrypted_and_plaintext_keys.yml')
                    )
                  )
                end
                let(:expected) do
                  {
                    "my_mapping" => {
                      "key" => 'f',
                      "another_key" => 'f'
                    }
                  }
                end
                it 'must return the contents of text encrypted using ansible-vault and also plaintext' do
                  content = described_class.decrypt(text: text, password: 'ansible')
                  expect(content).to eq(expected)
                end
              end
            end
          end

          # NOTE: Omit test for "sequence" node, since it does not represent a real scenario.
          # ansible/ansible-vault does not support it for "partial" encryption.
        end
      end
    end
  end
end
