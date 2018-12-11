# Changelog

## v 0.3.0 

* Add `Ansible::Vault::KeyValueDecryptor` that allows decryption of YAML (#12)
* Add `Ansible::Vault.decrypt_text` that decrypts only text using `Ansible::Vault::TextDecryptor` (#12)
* Add `Ansible::Vault.parse_and_decrypt_yaml` that decrypts only YAML using `Ansible::Vault::KeyValueDecryptor` (#12)
* Deprecate `Ansible::Vault.decrypt` in favor of `Ansible::Vault.decrypt_text` (#12)

## v 0.2.1

* Handle blank files in FileReader (#6)

## v 0.2.0
* Added checks for nil/blank passwords (#4)
* Added the ability to check if a file is encrypted (#3)

## v 0.1.0 Initial Release
* Implemented Read and write commands
