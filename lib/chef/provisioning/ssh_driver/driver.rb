require 'json'
require 'resolv'
require 'chef/provisioning/driver'
require 'chef/provisioning/version'
require 'chef/provisioning/machine/basic_machine'
require 'chef/provisioning/machine/unix_machine'
require 'chef/provisioning/machine/windows_machine'
require 'chef/provisioning/convergence_strategy/install_msi'
require 'chef/provisioning/convergence_strategy/install_cached'
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
        # ## Parameters
        # cluster_path - path to the directory containing the vagrant files, which
        #                should have been created with the vagrant_cluster resource.

        # Create a new ssh driver.
        #
        # ## Parameters
        # cluster_path - path to the directory containing the vagrant files, which
        #                should have been created with the vagrant_cluster resource.
        def initialize(driver_url, config)
          super
          scheme, cluster_path = driver_url.split(':', 2)
          @cluster_path = cluster_path
        end

        attr_reader :cluster_path

        def self.from_url(driver_url, config)
          Driver.new(driver_url, config)
        end

        def self.canonicalize_url(driver_url, config)
          scheme, cluster_path = driver_url.split(':', 2)
          cluster_path = File.expand_path(cluster_path || File.join(Chef::Config.config_dir, 'provisioning/ssh'))
          "ssh:#{cluster_path}"
        end

        def allocate_machine(action_handler, machine_spec, machine_options)
          ensure_ssh_cluster(action_handler) unless ::File.exists?(cluster_path)

          log_info("SSH Driver - allocate_machine - machine_spec = #{machine_spec.inspect}")
          log_info("SSH Driver - allocate_machine - machine_options = #{machine_options['transport_options']}")
          log_info("SSH Driver - allocate_machine - machine_options = #{machine_options.configs}")

          new_machine = false
          new_machine_options = {}
          current_machine_options = false

          if machine_options[:transport_options] && machine_options[:transport_options]['is_windows']

            machine_spec.location = {
              'driver_url' => driver_url,
              'driver_version' => Chef::Provisioning::SshDriver::VERSION,
              'target_name' => machine_spec.name,
              'ssh_file_path' => "#{cluster_path}/#{machine_spec.name}.json",
              'allocated_at' => Time.now.utc.to_s
            }

          else

            if machine_options[:transport_options]
              new_machine_options['transport_options'] = machine_options[:transport_options]
            elsif machine_options['transport_options']
              new_machine_options['transport_options'] = machine_options['transport_options']
            end

            if machine_options[:convergence_options]
              new_machine_options['convergence_options'] = machine_options[:convergence_options]
            elsif machine_options['convergence_options']
              new_machine_options['convergence_options'] = machine_options['convergence_options']
            end

            if machine_spec.location && ssh_machine_exists?(machine_spec.name)
              _current_machine_options = existing_machine_hash(machine_spec)
              current_machine_options  = stringify_keys(_current_machine_options.dup)
            end

            log_info "machine_spec.name #{machine_spec.name}"

            log_info "new_machine_options #{new_machine_options} \n\n current_machine_options #{current_machine_options}"


            machine_file_hash = updated_ssh_machine_file_hash(stringify_keys(new_machine_options),
                                                              stringify_keys(current_machine_options))

            raise 'machine File Hash Is Empty' unless machine_file_hash
            log_info("machine HASH = #{machine_file_hash}")

            if machine_file_hash && machine_file_hash['transport_options']
              host_for(machine_file_hash['transport_options'])
              initialize_ssh(machine_file_hash['transport_options'])
            end

            machine_updated = create_ssh_machine_file(action_handler,
                                                      machine_spec.name,
                                                      machine_file_hash)
            machine_options_for(machine_file_hash)

            log_info("STRIPPED machine HASH = #{machine_file_hash}")
            log_info("UNSTRIPPED machine HASH = #{machine_file_hash}")
            log_info "machine_options_for #{machine_options_for}"

            if machine_updated || !machine_spec.location
              machine_spec.location = {
                'driver_url' => driver_url,
                'driver_version' => Chef::Provisioning::SshDriver::VERSION,
                'target_name' => machine_spec.name,
                'ssh_file_path' => "#{cluster_path}/#{machine_spec.name}.json",
                'allocated_at' => Time.now.utc.to_s
              }

              # if machine_options[:transport_options]
              #   %w(winrm.host winrm.port winrm.username winrm.password).each do |key|
              #     machine_spec.location[key] = machine_options[:transport_options][key] if machine_options[:vagrant_options][key]
              #   end
              # end

              log_info("machine_spec.location= #{machine_spec.location}")
            end
          end
        end

        def ready_machine(action_handler, machine_spec, machine_options)
          allocate_machine(action_handler, machine_spec, machine_options)
          if machine_options[:transport_options] && machine_options[:transport_options]['is_windows']
            machine_for(machine_spec, machine_options)
          else
            machine_for(machine_spec, machine_options_for)
          end
        end

        def connect_to_machine(machine_spec, machine_options)
          if machine_options[:transport_options] && machine_options[:transport_options]['is_windows']
            machine_for(machine_spec, machine_options)
          else
            if machine_spec.location && ssh_machine_exists?(machine_spec.name)
              _current_machine_options = existing_machine_hash(machine_spec)
              current_machine_options  = stringify_keys(_current_machine_options.dup)
            end
            host_for(current_machine_options['transport_options'])
            initialize_ssh(current_machine_options['transport_options'])
            machine_for(machine_spec, machine_options_for(current_machine_options))
          end
        end

        def destroy_machine(action_handler, machine_spec, machine_options)
          delete_ssh_machine_file(action_handler, existing_ssh_machine_file(machine_spec.name))
          # allocate_machine(action_handler, machine_spec, machine_options)
          # convergence_strategy_for(node).delete_chef_objects(action_handler, node)
        end

        def stop_machine(action_handler, machine_spec, machine_options)
          #
          # What to do What to do.
          #
          # On one level there's really only one thing to do here,
          # shellout and halt, or shutdown -h now,
          # maybe provide abitily to pass some shutdown options
          #
          # But be vewwy vewwy careful:
          #
          # you better have console...
          # or be close to your datacenter
          #
        end

        def restart_machine(action_handler, machine_spec, machine_options)
          # allocate_machine(action_handler, machine_spec, machine_options)
          # Full Restart, POST BIOS and all
        end

        def reload_machine(action_handler, machine_spec, machine_options)
          # allocate_machine(action_handler, machine_spec, machine_options)
          # Use `kexec` here to skip POST and BIOS and all that noise.
        end

        # protected

        def ensure_ssh_cluster(action_handler)
          _cluster_path = cluster_path
          Chef::Provisioning.inline_resource(action_handler) do
            ssh_cluster _cluster_path
          end
        end

        def existing_machine_hash(machine_spec)
          raise("You Must Pass machine_spec unless existing_machine_hash exists") unless machine_spec
          if ssh_machine_exists?(machine_spec.name)
            existing_machine_hash = JSON.parse(File.read(existing_ssh_machine_file(machine_spec.name)))
            existing_machine_hash
            # else
            #   return false
            #   # raise('We have machine_spec.location but have no machine_spec.location["ssh_file_path"]. WTF?')
            # end
          else
            return false
          end
        end

        def delete_ssh_machine_file(action_handler, registry_file)
          log_info("registry_file = #{registry_file}")
          if ::File.exists?(registry_file)
            Chef::Provisioning.inline_resource(action_handler) do
              file registry_file do
                action :delete
              end
            end
          end
        end

        def ssh_machine_exists?(target_name)
          ::File.exists?(existing_ssh_machine_file(target_name))
        end

        def existing_ssh_machine_file(target_name)
          existing_ssh_machine_file = ::File.join(@cluster_path, "#{target_name}.json")
          existing_ssh_machine_file
        end

        def create_ssh_machine_file(action_handler, target_name, use_machine_options)
          log_info("File is = #{::File.join(@cluster_path, "#{target_name}.json")}")
          log_info("current_machine_options = #{use_machine_options.to_s}")
          stringify_keys(use_machine_options)
          file_path = existing_ssh_machine_file(target_name)
          options_parsed = ::JSON.parse(use_machine_options.to_json)
          json_machine_options = ::JSON.pretty_generate(options_parsed)
          Chef::Provisioning.inline_resource(action_handler) do
            file file_path do
              content json_machine_options
            end
          end
        end

        def updated_ssh_machine_file_hash(new_machine_options, current_machine_options)
          log_info "updated_ssh_machine_file_hash --\nnew_machine_options = #{new_machine_options}\ncurrent_machine_options = #{current_machine_options}"
          if new_machine_options && new_machine_options['convergence_options']
            use_convergence_options   = new_machine_options['convergence_options']
          else
            use_convergence_options = false
          end

          if new_machine_options && new_machine_options['transport_options']
            new_transport_options     = new_machine_options['transport_options']
          else
            false
          end

          if current_machine_options && current_machine_options['transport_options']
            current_transport_options = current_machine_options['transport_options']
          else
            current_transport_options = new_transport_options
          end
          transport_options_hash    = updated_transport_options_hash(new_transport_options,
                                                                     current_transport_options)
          new_hash = {}
          new_hash['convergence_options'] = use_convergence_options if use_convergence_options
          new_hash['transport_options']   = transport_options_hash
          stringify_keys(new_hash)
          return new_hash
        end

        def updated_transport_options_hash(new_transport_options, current_transport_options = false)
          log_info "updated_transport_options_hash - new_transport_options if #{new_transport_options}"
          current_transport_options = new_transport_options unless current_transport_options

          new_ip     = new_transport_options['ip_address']     rescue false
          current_ip = current_transport_options['ip_address'] rescue false
          if (new_ip && current_ip)
            raise 'IP Addr Does not match' unless (new_ip == current_ip)
          end
          ip_address = (current_ip || new_ip)

          new_hostname     = new_transport_options['hostname']     rescue false
          current_hostname = current_transport_options['hostname'] rescue false
          hostname         = (current_hostname || new_hostname)

          new_host     = new_transport_options['host']     rescue false
          current_host = current_transport_options['host'] rescue false
          given_host   = (current_host || new_host)

          raise 'We Gots No IP or Hostname. So, um, yeah.' unless (hostname ||
                                                                   ip_address ||
                                                                   given_host)

          new_username     = new_transport_options['username']     rescue false
          new_ssh_options_user = new_transport_options['ssh_options']['user'] rescue false
          current_username = current_transport_options['username'] rescue false
          current_ssh_options_user = current_transport_options['ssh_options']['user'] rescue false
          username         = (current_username || current_ssh_options_user || new_username ||new_ssh_options_user)

          opts = {}
          opts['host']       = given_host if given_host
          opts['hostname']   = hostname   if hostname
          opts['ip_address'] = ip_address if ip_address
          host = host_for(opts)

          current_transport_options ||= {}
          current_transport_options['ssh_options'] ||= {}
          current_transport_options['ssh_options']['keys'] = [] unless current_transport_options['ssh_options']['keys']
          new_transport_options ||= {}
          new_transport_options['ssh_options'] ||= {}
          new_transport_options['ssh_options']['user'] = username
          new_transport_options['ssh_options']['keys']     = [] unless new_transport_options['ssh_options']['keys']
          new_keys = Array(current_transport_options['ssh_options']['keys']).concat( Array(new_transport_options['ssh_options']['keys']) ) || false
          log_info("new_keys = #{new_keys}")

          new_hash = {}
          new_hash['host']                    = host
          new_hash['ip_address']              = ip_address      if ip_address
          new_hash['hostname']                = hostname        if hostname
          new_hash['ssh_options']             = {}
          new_hash['ssh_options']['keys']     = new_keys        if new_keys
          if new_transport_options && new_transport_options['ssh_options']
            new_hash['ssh_options']['password'] = new_transport_options['password'] if new_transport_options['password']
          end

          merged_transport_options        = Chef::Mixin::DeepMerge.merge(current_transport_options.to_hash, new_transport_options.to_hash)
          _merged_transport_options       = merged_transport_options.dup
          updated_transport_options_hash = _merged_transport_options.dup
          updated_transport_options_hash = Chef::Mixin::DeepMerge.merge(merged_transport_options, new_hash) unless new_hash.empty?
          ensure_has_keys_or_password(updated_transport_options_hash)
          log_info "updated_transport_options_hash = #{updated_transport_options_hash}"
          updated_transport_options_hash
        end

        def ensure_has_keys_or_password(transport_hash = false)
          if transport_hash &&  transport_hash['ssh_options']
            ssh_hash = transport_hash['ssh_options']
            keys = ssh_hash['keys'] || false
            password = ssh_hash['password'] || false
            has_either = (password || (keys && !keys.empty?))
          else
            has_either = false
          end
          raise 'No Keys OR Password, No Can Do Compadre' unless has_either
          return has_either ? true : false
        end

        def host_for(_transport_options)
          @target_host  = false
          log_info "_transport_options #{_transport_options}"
          transport_options = stringify_keys(_transport_options)

          target_ip   = transport_options['ip_address'] || false
          target_fqdn = transport_options['hostname']   || false
          target_host = transport_options['host']       || false

          raise "no target_ip or target_fqdn given" unless(target_ip ||
                                                           target_host ||
                                                           target_fqdn )
          if target_ip
            raise 'Invalid IP' unless ( target_ip =~ Resolv::IPv4::Regex ||
                                        target_ip =~ Resolv::IPv6::Regex )
            @target_host = target_ip
          elsif target_fqdn
            rh = Resolv::Hosts.new
            rd = Resolv.new
            begin
              rh.getaddress(target_fqdn)
              in_hosts_file = true
            rescue
              in_hosts_file = false
            end
            begin
              rd.getaddress(target_fqdn)
              in_dns = true
            rescue
              in_dns = false
            end
            raise 'Unresolvable Hostname' unless (in_hosts_file || in_dns)
            @target_host = target_fqdn
          elsif target_host
            @target_host = target_host
          else
            raise "aint got no target yo, that dog dont hunt"
          end
          log_debug("get_target_connection_method - @target_host: #{@target_host}")
          @target_host
        end

        def can_connect?(_ssh_options, host)
        end

        def initialize_ssh(transport_options, options = {})
          _transport_options_s = transport_options.dup
          _transport_options = symbolize_keys(_transport_options_s.dup)
          log_info "_transport_options is #{_transport_options}"
          ssh_options = _transport_options[:ssh_options]
          @host = _transport_options[:host] || false
          @username = ssh_options[:user] rescue false
          @ssh_options_for_transport = ssh_options_for(ssh_options)

          new_options = options.empty? ? options : symbolize_keys(options)
          new_options.merge!({:ssh_pty_enable => true}) unless new_options.has_key?(:ssh_pty_enable)
          new_options.merge!({:prefix => 'sudo '}) unless @username == 'root'
          @options = new_options
          test = Chef::Provisioning::Transport::SSH.new(@host, @username, @ssh_options_for_transport, @options, config)
          test.available?
        end

        def machine_options_for(given_machine_options = false)
          if @machine_options_for
            log_info "@machine_options_for #{@machine_options_for}"
            return @machine_options_for
          else
            @machine_options_for ||= begin
              _given_machine_options = given_machine_options.dup
              ret_val = false
              ret_val = symbolize_keys(_given_machine_options) if _given_machine_options
              ret_val
            end
          end
        end

        def machine_for(machine_spec, machine_options)
          if machine_options[:transport_options]['is_windows']
            Chef::Provisioning::Machine::WindowsMachine.new(machine_spec, create_winrm_transport(machine_options),
                                                            convergence_strategy_for(machine_spec, machine_options))
          else
            Chef::Provisioning::Machine::UnixMachine.new(machine_spec,
                                                         transport_for(machine_options),
                                                         convergence_strategy_for(machine_spec, machine_options))
          end
        end

        def transport_for(machine_options)
          if machine_options[:transport_options]['is_windows']
            create_winrm_transport(machine_spec)
          else
            Chef::Provisioning::Transport::SSH.new(@target_host, @username, @ssh_options_for_transport, @options, config)
          end
        end

        def convergence_strategy_for(machine_spec, machine_options)
          if machine_options[:transport_options]['is_windows']
            @windows_convergence_strategy ||= begin
              Chef::Provisioning::ConvergenceStrategy::InstallMsi.
                new(machine_options[:convergence_options], config)
            end
          else
            @unix_convergence_strategy ||= begin
              Chef::Provisioning::ConvergenceStrategy::InstallCached.new(machine_options[:convergence_options],
                                                                         config)
            end
          end
        end

        def create_winrm_transport(machine_options)
          # forwarded_ports = machine_options[:transport_options]['forwarded_ports']

          # TODO IPv6 loopback?  What do we do for that?
          hostname = machine_options[:transport_options]['host'] || '127.0.0.1'
          port = machine_options[:transport_options]['port'] || 5985
          # port = forwarded_ports[port] if forwarded_ports[port]
          endpoint = "http://#{hostname}:#{port}/wsman"
          type = :plaintext
          options = {
            :user => machine_options[:transport_options]['user'] || 'vagrant',
            :pass => machine_options[:transport_options]['password'] || 'vagrant',
            :disable_sspi => true
          }

          Chef::Provisioning::Transport::WinRM.new(endpoint, type, options, config)
        end

        # def create_ssh_transport(machine_options)
        def ssh_options_for(given_ssh_options)
          machine_ssh_options = stringify_keys(given_ssh_options)
          # username = (@username || machine_ssh_options['user'] || ENV['METAL_SSH_USER'] || 'root')
          log_info("machine_ssh_options: #{machine_ssh_options}")

          ssh_pass = machine_ssh_options['password'] || false
          ssh_pass_hash = { 'password' => ssh_pass } if ssh_pass

          ssh_keys = []
          if machine_ssh_options['keys']
            Array(machine_ssh_options['keys']).each do |key|
              ssh_keys << key
            end
          else
            ssh_keys = false
          end

          ssh_key_hash = { 'keys' => ssh_keys.flatten.uniq } if ssh_keys

          log_info("create_ssh_transport - ssh_pass: #{ssh_pass}") if ssh_pass
          log_info("create_ssh_transport - ssh_keys: #{ssh_keys.inspect}") if ssh_keys
          log_info("create_ssh_transport - no ssh_pass or ssh_key given") unless (ssh_keys || ssh_pass)
          raise "no ssh_pass or ssh_key given" unless ( ssh_pass || ssh_keys )
          machine_ssh_options.merge!(ssh_pass_hash) if ssh_pass_hash
          machine_ssh_options.merge!(ssh_key_hash) if ssh_key_hash

          # Validate Ssh Options
          use_ssh_options = symbolize_keys(machine_ssh_options)
          log_info "use_ssh_options #{use_ssh_options}"
          use_ssh_options.each { |k,v| raise "Invalid Shh Option #{k} \n Valid Options are #{valid_ssh_options}" unless valid_ssh_options.include?(k) }

          # Make Sure We Can Connect
          log_debug("create_ssh_transport - ssh_options: #{use_ssh_options.inspect}")
          begin
            ssh = Net::SSH.start(@target_host, @username, use_ssh_options)
            ssh.close
            log_info("ABLE to Connect to #{@target_host} using #{@username} and #{use_ssh_options.inspect}")
          rescue
            log_info("UNABLE to Connect to #{@target_host} using #{@username} and #{use_ssh_options.inspect}")
            raise "UNABLE to Connect to #{@target_host} using #{@username} and #{use_ssh_options.inspect}"
          end

          return use_ssh_options
        end

      end
    end
  end
end
