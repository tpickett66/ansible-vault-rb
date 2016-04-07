require 'spec_helper'

describe Ansible::Vault do
  it 'has a version number' do
    expect(Ansible::Vault::VERSION).not_to be nil
  end

  it 'does something useful' do
    expect(false).to eq(true)
  end
end
