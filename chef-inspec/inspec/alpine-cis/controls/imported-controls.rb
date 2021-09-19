#
# The "include_controls" command brings in all controls for the named profile.
# In this example, all controls from the "linux-baseline" profile will be run
# against our target every time our profile is executed.
#
# Profiles to be included/inherited must be defined in the "depends" section of
# the inspec.yml.
#
include_controls 'cis-dil-benchmark' do
  # In the event there is a control from an inherited profile that should not be
  # run, it can be skipped with the "skip_control" command. In this example,
  # InSpec will not run the "os-05" control from the "linux-baseline" profile
  # even though we've told InSpec to run all controls from "linux-baseline".
# Kernel Modules - Not Relevant
skip_control 'cis-dil-benchmark-1.1.1.1'
skip_control 'cis-dil-benchmark-1.1.1.2'
skip_control 'cis-dil-benchmark-1.1.1.3'
skip_control 'cis-dil-benchmark-1.1.1.4'
skip_control 'cis-dil-benchmark-1.1.1.5'
skip_control 'cis-dil-benchmark-1.1.1.6'
skip_control 'cis-dil-benchmark-1.1.1.7'
skip_control 'cis-dil-benchmark-1.1.1.8'
skip_control 'cis-dil-benchmark-1.1.23'

# Seperate Partitions - Not Relevant
skip_control 'cis-dil-benchmark-1.1.2'
skip_control 'cis-dil-benchmark-1.1.3'
skip_control 'cis-dil-benchmark-1.1.4'
skip_control 'cis-dil-benchmark-1.1.5'

# No AIDE 
skip_control 'cis-dil-benchmark-1.3.1'
skip_control 'cis-dil-benchmark-1.3.2'

# No Bootloader
skip_control 'cis-dil-benchmark-1.4.1'
skip_control 'cis-dil-benchmark-1.4.2'
skip_control 'cis-dil-benchmark-1.4.3'

# No ntpd
skip_control 'cis-dil-benchmark-2.2.1.2'

# No iptables
skip_control 'cis-dil-benchmark-3.5.1.1'
skip_control 'cis-dil-benchmark-3.5.1.2'
skip_control 'cis-dil-benchmark-3.5.1.3'
skip_control 'cis-dil-benchmark-3.5.2.1'
skip_control 'cis-dil-benchmark-3.5.2.2'
skip_control 'cis-dil-benchmark-3.5.2.3'
skip_control 'cis-dil-benchmark-3.5.3'

# Logs are done via STDOUT/STDERR
skip_control 'cis-dil-benchmark-4.2.1.3'
skip_control 'cis-dil-benchmark-4.2.1.4'
skip_control 'cis-dil-benchmark-4.2.1.5'
skip_control 'cis-dil-benchmark-4.2.1.1'

# No Cron
skip_control 'cis-dil-benchmark-5.1.1'
skip_control 'cis-dil-benchmark-5.1.2'
skip_control 'cis-dil-benchmark-5.1.3'
skip_control 'cis-dil-benchmark-5.1.4'
skip_control 'cis-dil-benchmark-5.1.5'
skip_control 'cis-dil-benchmark-5.1.6'
skip_control 'cis-dil-benchmark-5.1.7'
skip_control 'cis-dil-benchmark-5.1.8'

# No ssh
skip_control 'cis-dil-benchmark-5.2.1'
skip_control 'cis-dil-benchmark-5.2.13'
skip_control 'cis-dil-benchmark-5.2.14'
skip_control 'cis-dil-benchmark-5.2.15'
skip_control 'cis-dil-benchmark-5.2.18'

# No sysctl 
skip_control 'cis-dil-benchmark-3.1.1'
skip_control 'cis-dil-benchmark-3.1.2'
skip_control 'cis-dil-benchmark-3.2.1'
skip_control 'cis-dil-benchmark-3.2.2'
skip_control 'cis-dil-benchmark-3.2.3'
skip_control 'cis-dil-benchmark-3.2.4'
skip_control 'cis-dil-benchmark-3.2.5'
skip_control 'cis-dil-benchmark-3.2.6'
skip_control 'cis-dil-benchmark-3.2.7'
skip_control 'cis-dil-benchmark-3.2.8'
skip_control 'cis-dil-benchmark-3.2.9'

# No tcpd
skip_control 'cis-dil-benchmark-3.3.1'
skip_control 'cis-dil-benchmark-3.3.2'
skip_control 'cis-dil-benchmark-3.3.3'
skip_control 'cis-dil-benchmark-3.3.4'
skip_control 'cis-dil-benchmark-3.3.5'

# No su
skip_control 'cis-dil-benchmark-5.6'



end

# require_controls
#
#require_controls 'cis-dil-benchmark' do

#control 'a-control-1.1.1''

#end
