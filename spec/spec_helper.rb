require 'pathname'
$LOAD_PATH.unshift File.expand_path('../../lib', __FILE__)
require 'ansible/vault'

SPEC_PATH = Pathname.new(File.expand_path('..', __FILE__))
FIXTURE_PATH = SPEC_PATH.join('fixtures')

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
end
