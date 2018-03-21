This is a custom sysmodule for Nintendo Switch, however this can also be run as a regular app. This registers+handles custom services.

IPC (MITM) logging is also included.

This is basically native RPC accessible over USB or IPC. For USB just run `sysmodule_client.py` with host<>Switch USB connected while this process is running. See sysmodule_client.py source for commands. The client can be restarted whenever if no commands are being used. Do not leave USB connected when entering sleep-mode.

Note that as a regular-app, this wouldn't init gfx or handle {exit via HID button}.

## Credits
* This uses .py based on rop-rpc.
