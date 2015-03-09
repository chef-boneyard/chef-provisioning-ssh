require 'chef/resource/lwrp_base'
require 'chef/provisioning/ssh_driver'

class Chef::Resource::SshCluster < Chef::Resource::LWRPBase
 self.resource_name = 'ssh_cluster'

 actions :create, :delete, :nothing
 default_action :create

 attribute :path, :kind_of => String, :name_attribute => true

  def after_created
    super
    run_context.chef_provisioning.with_driver "ssh:#{path}"
  end

  # We are not interested in Chef's cloning behavior here.
  def load_prior_resource(*args)
    Chef::Log.debug("Overloading #{resource_name}.load_prior_resource with NOOP")
  end
end
