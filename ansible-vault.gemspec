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
  spec.description   = %q{A ruby implementation of Ansible's vault utilities}
  spec.homepage      = "TODO: Put your gem's website or public repo URL here."

  spec.files         = `git ls-files -z`.split("\x0").reject { |f| f.match(%r{^(test|spec|features)/}) }
  spec.bindir        = "exe"
  spec.executables   = spec.files.grep(%r{^exe/}) { |f| File.basename(f) }
  spec.require_paths = ["lib"]

  spec.add_development_dependency "bundler", "~> 1.11"
  spec.add_development_dependency "rake", "~> 10.0"
  spec.add_development_dependency "rspec", "~> 3.0"
  spec.add_development_dependency "guard-rspec"
end
