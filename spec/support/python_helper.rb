require 'open3'

module PythonHelper
  class << self
    attr_accessor :python_path
  end

  def detect_python
    stdout, stderr, status = Open3.capture3(%q{/usr/bin/env bash -c 'command -v python'})
    if status.exitstatus == 0
      PythonHelper.python_path = stdout.chomp
    else
      warn('Python not found on $PATH, disabling tests using python')
    end
  end

  def exec_python(program)
    stdout, stderr, status = Open3.capture3("python -c '#{program}'")
    if status.exitstatus != 0
      err = [
        "Execution of python program '#{program}' failed!",
      "STDOUT: #{stdout}",
      "STDERR: #{stderr}"
      ].join("\n")
      raise err
    end
    stdout.chomp
  end
end
