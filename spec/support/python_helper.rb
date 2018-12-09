require 'open3'

module PythonHelper
  class << self
    attr_accessor :ansible_vault_path, :python_path
  end

  def ansible_vault_decrypt(path:, password:)
    Tempfile.open('vault-password', TMP_PATH.to_s) { |password_file|
      password_file.write(password)
      password_file.fsync
      command = [
        "#{PythonHelper.ansible_vault_path}",
        "decrypt",
        "--vault-password-file=#{password_file.path}",
        path
      ].join(' ')
      stdout, stderr, status = Open3.capture3(command)
      if status.exitstatus != 0
        raise [
          "Execution of ansible-vault decrypt failed!",
          "STDOUT: #{stdout}",
          "STDERR: #{stderr}",
          "Password file contents: #{File.read(password_file.path)}",
          "Vault contents: #{File.read(path)}"
        ].join("\n")
      end
    }
  end

  def detect_ansible
    stdout, _, status = Open3.capture3(%q{/usr/bin/env bash -c 'command -v ansible-vault'})
    if status.exitstatus == 0
      PythonHelper.ansible_vault_path = stdout.chomp
    else
      warn('Ansible Vault not found on $PATH, disabling tests using ansible-vault')
    end
  end

  def detect_python(binary_name)
    stdout, _, status = Open3.capture3("/usr/bin/env bash -c 'command -v #{binary_name}'")
    if status.exitstatus == 0
      PythonHelper.python_path = stdout.chomp
    else
      warn('Python not found on $PATH, disabling tests using python')
    end
  end

  def exec_python(program)
    stdout, stderr, status = Open3.capture3("#{PythonHelper.python_path} -c '#{program}'")
    if status.exitstatus != 0
      raise [
        "Execution of python program '#{program}' failed!",
        "STDOUT: #{stdout}",
        "STDERR: #{stderr}"
      ].join("\n")
    end
    stdout.chomp
  end
end
