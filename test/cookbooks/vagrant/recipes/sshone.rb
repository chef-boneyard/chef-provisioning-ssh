#
# Cookbook Name:: vagrant
# Recipe:: sshone
#

file '/tmp/sshone.txt' do
	action :create
	owner 'root'
	group 'root'
	mode '0644'
end
