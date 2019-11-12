require 'chef/provider/lwrp_base'
require 'cheffish'

class Chef::Provider::SshCluster < Chef::Provider::LWRPBase

  use_inline_resources
  provides :ssh_cluster

  def whyrun_supported?
    true
  end

  action :create do
    the_base_path = new_resource.path
    Cheffish.inline_resource(self, :create) do
      directory the_base_path do
        recursive true
      end
    end
  end

  action :delete do
    the_base_path = new_resource.path
    Cheffish.inline_resource(self, :delete) do
      directory the_base_path do
        recursive true
        action :delete
      end
    end
  end

  def load_current_resource
  end

end
