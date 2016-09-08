# coding: utf-8
lib = File.expand_path('../lib', __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require 'ansible/vault/version'

Gem::Specification.new do |spec|
  spec.name          = "ansible-vault"
  spec.version       = Ansible::Vault::VERSION
  spec.authors       = ["Tyler Pickett"]
  spec.email         = ["t.pickett66@gmail.com"]

  spec.summary       = %q{A ruby implementation of Ansible's vault utilities}
  spec.description   = "A ruby implementation of Ansible's vault utilities. " \
   "Currently supports the AES256 variant, no support for the original AES" \
   "format is planned."
  spec.homepage      = "https://github.com/tpickett66/ansible-vault-rb"

  spec.files         = `git ls-files -z`.split("\x0").reject { |f| f.match(%r{^(test|spec|features)/}) }
  spec.bindir        = "exe"
  spec.executables   = spec.files.grep(%r{^exe/}) { |f| File.basename(f) }
  spec.require_paths = ["lib"]
  spec.license        = "MIT"

  spec.add_dependency "oroku_saki", "~> 1.1"

  spec.add_development_dependency "bundler", "~> 1.11"
  spec.add_development_dependency "rake", "~> 10.0"
  spec.add_development_dependency "rspec", "~> 3.0"
  spec.add_development_dependency "guard-rspec", "~> 4.6"
  spec.add_development_dependency "listen", "< 3.1.0"
  spec.add_development_dependency "byebug", "~> 8.2"
  spec.add_development_dependency "yard", "~> 0.8.7"

  spec.required_ruby_version = '>= 2.1.0'
end
