module FixtureHelpers
  def fixture_path(*path_parts)
    FIXTURE_PATH.join(*path_parts).to_s
  end
end
