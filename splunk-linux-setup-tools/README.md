# Splunk Installation
These are just a few files and scripts to make setting up a Splunk server easier.

## Samba
Having Samba running on your Splunk server if very helpful. You can use it to 
deploy Universal Forwarders, upload scripts, and more.

The smb.conf is a reference file. Changes should be made down towards the bottom.


## NTP
Network Time Protocol is needed for your lab, but you don't want your vulnable
virtual machines having access to the Internet. So, it's best to have the Splunk
server offer NTP service. You'll need this to ensure event times are processing 
correctly on the event sources. Otherwise, you might have issues with event times 
inside Splunk (i.e. events might show timestamps in the future).
