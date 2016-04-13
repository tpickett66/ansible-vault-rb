# Ansible::Vault
[![Build Status](https://travis-ci.org/tpickett66/ansible-vault-rb.svg?branch=master)](https://travis-ci.org/tpickett66/ansible-vault-rb)

A ruby implementation of the Ansible vault file format for use in tooling that
needs to work with the vaults but doesn't want to shell out. The goal is to
provide an IO like API for interacting with the files, basic reading and
writing will be implemented first with a stream interface coming later if the
need arises. The API design is inspired by Ruby's IO class for ease of adoption
and [http://nacl.cr.yp.to/](NaCl's crypto_box) in that it takes care of doing
the right things for the user.

## Installation

Add this line to your application's Gemfile:

```ruby
gem 'ansible-vault'
```

And then execute:

    $ bundle

Or install it yourself as:

    $ gem install ansible-vault

## Usage

### Reading the contents of a vault (Status: Completed)

```ruby
require 'ansible/vault'

contents = Ansible::Vault.read(path: '/path/to/file', password: 'foobar')
  # => 'These are the secrets that I keep.'
```

Yep, that's it! This call opens the vault file, verifies the included HMAC, and
(assuming the HMAC checks out) decrypts the contents of the file and returns
the String representation of the contents.

### Writing new contents to a vault (Status: In Progress)

```ruby
require 'ansible/vault'

Ansible::Vault.write({
  path: '/path/to/file',
  password: 'foobar',
  contents: 'My secrets.'
}) # => true
```

This call overwrites anything at the path specified with the cyphertext of the
supplied contents. The contents are expected to have been cast to a string
prior to being supplied to this function.

## Development

After checking out the repo, run `bin/setup` to check for the required
dependencies. Then, run `rake spec` to run the tests. You can also run
`bin/console` for an interactive prompt that will allow you to experiment.

To install this gem onto your local machine, run `bundle exec rake install`. To
release a new version, update the version number in `version.rb`, and then run
`bundle exec rake release`, which will create a git tag for the version, push
git commits and tags, and push the `.gem` file to
[rubygems.org](https://rubygems.org).

## Contributing

Bug reports and pull requests are welcome on GitHub at
https://github.com/tpickett66/ansible-vault-rb.

