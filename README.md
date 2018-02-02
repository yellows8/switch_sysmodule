This is a custom sysmodule for Nintendo Switch. This registers+handles custom services, with that disabled this should be usable (untested) as a regular app.

IPC (MITM) logging is also included.

This is basically native RPC accessible over USB or IPC. For USB just run `sysmodule_client.py` with host<>Switch USB connected while this process is running. See sysmodule_client.py source for commands. The client can be restarted whenever if no commands are being used. Do not leave USB connected when entering sleep-mode.

Some of these commands use privileged SVCs which regular apps don't have access to.

## Credits
* This uses .py based on rop-rpc.
