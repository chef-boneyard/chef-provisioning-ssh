require 'chef/provisioning/ssh_driver'

with_driver 'ssh'

# Run this recipe AFTER running test_ssh or it will fail
# It tests that we don't need to specify machine_options
# for existing nodes
machine "sshone" do
  run_list [ 'recipe[vagrant::sshone_2]' ]
  action :converge
end

machine "sshone" do
  action :destroy
end


with_driver 'ssh:chef'

machine "sshtwo" do
  run_list [ 'recipe[vagrant::sshtwo_2]' ]
  action :converge
end

machine "sshtwo" do
  action :destroy
end

machine "sshthree" do
  run_list [ 'recipe[vagrant::sshthree_2]' ]
  action :converge
end

machine "sshthree" do
  action :destroy
end
