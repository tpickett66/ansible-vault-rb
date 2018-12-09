require 'pathname'
require 'fileutils'
$LOAD_PATH.unshift File.expand_path('../../lib', __FILE__)
require 'ansible/vault'

SPEC_PATH = Pathname.new(File.expand_path('..', __FILE__))
FIXTURE_PATH = SPEC_PATH.join('fixtures')
TMP_PATH = SPEC_PATH.join('..', 'tmp')
FileUtils.mkdir_p(TMP_PATH.to_s)

Dir[SPEC_PATH.join('support', '**', '*.rb')].each do |path|
  require path
end

RSpec.configure do |config|
  config.disable_monkey_patching!

  config.order = :random
  Kernel.srand config.seed

  config.filter_run :focus
  config.run_all_when_everything_filtered = true

  if config.files_to_run.one?
    config.default_formatter = 'doc'
  end

  config.profile_examples = 10

  config.include FixtureHelpers
  config.include PythonHelper

  config.before(:all) do
    detect_python('python2')
    detect_ansible
  end

  config.before do |example|
    if example.metadata[:python] && !PythonHelper.python_path
      pending('Pending due to missing python')
    elsif example.metadata[:ansible_vault] && !PythonHelper.ansible_vault_path
      pending('Pending due to missing ansible-vault')
    end
  end
end
