This is a custom sysmodule for Nintendo Switch, however this can also be run as a regular app. This registers+handles custom services.

IPC (MITM) logging is also included.

This is basically native RPC accessible over USB or IPC. For USB just run `sysmodule_client.py` with host<>Switch USB connected while this process is running. See sysmodule_client.py source for commands. The client can be restarted whenever if no commands are being used. If built with `make NETWORK=1`, networking will be used instead of USB (pass the server address to `sysmodule_client.py` for this).

Note that as a regular-app, this wouldn't init gfx or handle {exit via HID button}.

Building requires a 0x20-byte file at `data/auth.bin`, this should contain random data.

## Credits
* This uses .py based on rop-rpc.
