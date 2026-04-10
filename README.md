# Invoke-LoginFailureMonitor
This script monitors login failures and blocks the source ip by adding a firewall rule to the Windows firewall. This script comes with no warranty or support. Users are responsible for their own security.

# Usage
Run this script under local system, or better, a service account which has access to the Security event log and ability to modify the firewall. Enable the script to run at startup. Firewall rules that are created by the script are formatted as PSFailMod_BLOCK_<Offending_IP>.

# Remarks
This script needs additional work though has been tested via RDP (Logon Type 10) and Network (Logon Type 3) login attempts.
