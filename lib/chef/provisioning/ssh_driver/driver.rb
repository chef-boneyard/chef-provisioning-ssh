require 'json'
require 'resolv'
require 'chef/provisioning/driver'
require 'chef/provisioning/version'
require 'chef/provisioning/machine/basic_machine'
require 'chef/provisioning/machine/unix_machine'
require 'chef/provisioning/machine/windows_machine'
require 'chef/provisioning/convergence_strategy/install_msi'
require 'chef/provisioning/convergence_strategy/install_sh'
require 'chef/provisioning/transport/winrm'
require 'chef/provisioning/transport/ssh'
require 'chef/provisioning/ssh_driver/version'
require 'chef/provisioning/ssh_driver/helpers'
require 'chef/resource/ssh_cluster'
require 'chef/provider/ssh_cluster'

class Chef
  module Provisioning
    module SshDriver
      # Provisions Machines Using SSH.
      class Driver < Chef::Provisioning::Driver

        include Chef::Provisioning::SshDriver::Helpers

        attr_reader :cluster_path

        def self.from_url(driver_url, config)
          Driver.new(driver_url, config)
        end

        def initialize(driver_url, config)
          super(driver_url, config)
          scheme, cluster_path = driver_url.split(':', 2)
          @cluster_path = cluster_path
        end

        def self.canonicalize_url(driver_url, config)
          scheme, cluster_path = driver_url.split(':', 2)
          cluster_path = File.expand_path(cluster_path || File.join(Chef::Config.config_dir, 'provisioning/ssh'))
          "ssh:#{cluster_path}"
        end

        def allocate_machine(action_handler, machine_spec, machine_options)
          existing_machine = existing_ssh_machine(machine_spec)
          if !existing_machine
            validate_machine_options(action_handler, machine_spec, machine_options)
            ensure_ssh_cluster(action_handler)
            ssh_machine = create_ssh_machine(action_handler, machine_spec, machine_options)
            machine_spec.location = {
              'driver_url' => driver_url,
              'driver_version' => Chef::Provisioning::SshDriver::VERSION,
              'target_name' => machine_spec.name,
              'ssh_machine_file' => ssh_machine,
              'allocated_at' => Time.now.utc.to_s
            }
          end
        end

        def ready_machine(action_handler, machine_spec, machine_options)
          ssh_machine = existing_ssh_machine(machine_spec)

          if !ssh_machine
            raise "SSH Machine #{machine_spec.name} does not have a machine file associated with it!"
          end

          wait_for_transport(action_handler, ssh_machine, machine_spec, machine_options)
          machine_for(machine_spec, machine_options)
        end

        def connect_to_machine(machine_spec, machine_options)
          machine_for(machine_spec, machine_options)
        end

        def destroy_machine(action_handler, machine_spec, machine_options)
          ssh_machine = existing_ssh_machine(machine_spec)

          if !ssh_machine
            raise "SSH Machine #{machine_spec.name} does not have a machine file associated with it!"
          end


        end

        def stop_machine(action_handler, machine_spec, machine_options)
          ssh_machine = existing_ssh_machine(machine_spec)

          if !ssh_machine
            raise "SSH Machine #{machine_spec.name} does not have a machine file associated with it!"
          end

          action_handler.report_progress("SSH Machine #{machine_spec.name} is existing hardware login and power off.")
        end

        def machine_for(machine_spec, machine_options)
          ssh_machine = existing_ssh_machine(machine_spec)

          if !ssh_machine
            raise "SSH Machine #{machine_spec.name} does not have a machine file associated with it!"
          end

          if ssh_machine[:is_windows]
            Chef::Provisioning::Machine::WindowsMachine.new(machine_spec,
                                                            transport_for(ssh_machine),
                                                            convergence_strategy_for(ssh_machine))
          else
            Chef::Provisioning::Machine::UnixMachine.new(machine_spec,
                                                         transport_for(ssh_machine),
                                                         convergence_strategy_for(ssh_machine))
          end
        end

        def transport_for(ssh_machine)
          if ssh_machine[:is_windows]
            create_winrm_transport(ssh_machine)
          else
            create_ssh_transport(ssh_machine)
          end
        end

        def convergence_strategy_for(ssh_machine)
          if ssh_machine[:is_windows]
            Chef::Provisioning::ConvergenceStrategy::InstallMsi.
                new(ssh_machine[:convergence_options], config)
          else
            Chef::Provisioning::ConvergenceStrategy::InstallSh.
                new(ssh_machine[:convergence_options], config)
          end
        end

        def create_ssh_transport(ssh_machine)
          hostname = ssh_machine[:transport_options][:host] ||
                     ssh_machine[:transport_options][:ip_address]
          username = ssh_machine[:transport_options][:username]
          ssh_options = ssh_machine[:transport_options][:ssh_options] ?
                          ssh_machine[:transport_options][:ssh_options] : {}
          options = ssh_machine[:transport_options][:options] ?
                      ssh_machine[:transport_options][:options] : {}
          Chef::Provisioning::Transport::SSH.new(hostname, username,
                                                 ssh_options, {:prefix => 'sudo '}, config)
        end

        def create_winrm_transport(ssh_machine)
          # TODO IPv6 loopback?  What do we do for that?
          hostname = ssh_machine[:transport_options][:host] ||
                     ssh_machine[:transport_options][:ip_address]
          port = ssh_machine[:transport_options][:port] || 5985
          # port = forwarded_ports[port] if forwarded_ports[port]
          endpoint = "http://#{hostname}:#{port}/wsman"
          type = :plaintext
          options = {
            :user => ssh_machine[:transport_options][:username],
            :pass => ssh_machine[:transport_options][:password],
            :disable_sspi => true
          }

          Chef::Provisioning::Transport::WinRM.new(endpoint, type, options, config)
        end

        def wait_for_transport(action_handler, ssh_machine, machine_spec, machine_options)
          time_elapsed = 0
          sleep_time = 10
          max_wait_time = 120
          transport = transport_for(ssh_machine)
          unless transport.available?
            if action_handler.should_perform_actions
              action_handler.report_progress "waiting for #{machine_spec.name} (#{ssh_machine[:transport_options][:ip_address]} on #{driver_url}) to be connectable (transport up and running) ..."
              while time_elapsed < max_wait_time && !transport.available?
                action_handler.report_progress "been waiting #{time_elapsed}/#{max_wait_time} -- sleeping #{sleep_time} seconds for #{machine_spec.name} (#{ssh_machine[:transport_options][:ip_address]} on #{driver_url}) to be connectable ..."
                sleep(sleep_time)
                time_elapsed += sleep_time
              end
              unless transport.available?
                raise "Machine #{machine_spec.name} (#{ssh_machine[:transport_options][:ip_address]} on #{driver_url}) did not become ready within 120 seconds"
              end
              action_handler.report_progress "#{machine_spec.name} is now connectable"
            end
          end
        end

        def validate_machine_options(action_handler, machine_spec, machine_options)
          error_msgs = []
          valid = true

          if !machine_options[:transport_options]
            error_msgs << ":transport_options required."
            valid = false
          else
            if machine_options[:transport_options][:is_windows]
              # Validate Windows Options.
              req_and_valid_fields = [:is_windows, [:host, :ip_address], :username, :password]
              one_of_fields = req_and_valid_fields.select{ |i| i.kind_of?(Array)}

              missing = req_and_valid_fields.flatten - machine_options[:transport_options].keys

              for oof in one_of_fields
                if oof == oof & missing
                  error_msgs << ":transport_options => :#{oof.join(" or :")} required."
                end
                missing -= oof
              end

              for missed in missing do
                error_msgs << ":transport_options => :#{missed} required."
                valid = false
              end

              extras = machine_options[:transport_options].keys - req_and_valid_fields.flatten

              for extra in extras do
                error_msgs << ":transport_options => :#{extra} not allowed."
                valid = false
              end
            else
              # Validate Unix Options
              req_fields = [[:host, :ip_address], :username]
              one_of_fields = req_fields.select{ |i| i.kind_of?(Array)}

              missing = req_fields.flatten - machine_options[:transport_options].keys

              for oof in one_of_fields
                if oof == oof & missing
                  error_msgs << ":transport_options => :#{oof.join(" or :")} required."
                end
                missing -= oof
              end

              for missed in missing do
                error_msgs << ":transport_options => :#{missed} required."
                valid = false
              end

              valid_fields = [:is_windows, :host, :ip_address, :username, :ssh_options, :options]

              extras = machine_options[:transport_options].keys - valid_fields

              for extra in extras do
                error_msgs << ":transport_options => :#{extra} not allowed."
                valid = false
              end

              if machine_options[:transport_options][:ssh_options]
                valid_fields = valid_ssh_options

                extras = machine_options[:transport_options][:ssh_options].keys - valid_fields

                for extra in extras do
                  error_msgs << ":transport_options => ssh_options => :#{extra} not allowed."
                  valid = false
                end
              end

              if machine_options[:transport_options][:options]
                valid_fields = [:prefix, :ssh_pty_enable, :ssh_gateway]

                extras = machine_options[:transport_options][:options].keys - valid_fields

                for extra in extras do
                  error_msgs << ":transport_options => :options => :#{extra} not allowed."
                  valid = false
                end
              end
            end
          end

          if !valid
            exception_string = "Machine Options for #{machine_spec.name} are invalid cannot create machine."
            for string in error_msgs do
              exception_string = "#{exception_string}\n  #{string}"
            end
            raise exception_string
          end
        end

        def ensure_ssh_cluster(action_handler)
          _cluster_path = cluster_path
          Chef::Provisioning.inline_resource(action_handler) do
            ssh_cluster _cluster_path
          end
        end

        def create_ssh_machine(action_handler, machine_spec, machine_options)
          log_info("File is = #{ssh_machine_file(machine_spec)}")
          log_info("current_machine_options = #{machine_options.to_s}")
          machine_options_hash = deep_hashify(machine_options)
          stringy_machine_options = stringify_keys(machine_options_hash)
          file_path = ssh_machine_file(machine_spec)
          options_parsed = ::JSON.parse(stringy_machine_options.to_json)
          json_machine_options = ::JSON.pretty_generate(options_parsed)
          Chef::Provisioning.inline_resource(action_handler) do
            file file_path do
              content json_machine_options
            end
          end
          file_path
        end

        def delete_ssh_machine(action_handler, machine_spec)
          if ::File.exists?(ssh_machine_file(machine_spec))
            Chef::Provisioning.inline_resource(action_handler) do
              file registry_file do
                action :delete
              end
            end
          end
        end

        def existing_ssh_machine(machine_spec)
          if ssh_machine_exists?(machine_spec)
            existing_machine_hash = JSON.parse(File.read(ssh_machine_file(machine_spec)))
            symbolize_keys(existing_machine_hash.to_hash)
          else
            return false
          end
        end

        def ssh_machine_exists?(machine_spec)
          if machine_spec.location
            ::File.exists?(ssh_machine_file(machine_spec))
          else
            false
          end
        end

        def ssh_machine_file(machine_spec)
          if machine_spec.location && machine_spec.location['ssh_machine_file']
            machine_spec.location['ssh_machine_file']
          else
            ssh_machine_file = ::File.join(@cluster_path, "#{machine_spec.name}.json")
            ssh_machine_file
          end
        end
      end
    end
  end
end
