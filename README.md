# aiohmi

Pyghmi is a pure Python (mostly IPMI) server management library.

## Building and installing

(These instructions have been tested on CentOS 7)

Clone the repository, generate the RPM and install it:
```bash
$ git clone https://github.com/jjohnson42/aiohmi.git
$ cd aiohmi/
$ python setup.py bdist_rpm
$ sudo rpm -ivh dist/aiohmi-*.noarch.rpm
```

## Using

There are a few use examples in the `bin` folder:

- `fakebmc`: simply fakes a BMC that supports a few IPMI commands (useful for
  testing)
- `aiohmicons`: a remote console based on SOL redirection over IPMI
- `aiohmiutil`: an IPMI client that supports a few direct uses of aiohmi (also
  useful for testing and prototyping new features)
- `virshbmc`: a BMC emulation wrapper using libvirt


## Extending

If you plan on adding support for new features, you'll most likely be interested
in adding your methods to `aiohmi/ipmi/command.py`. See methods such as
`get_users` and `set_power` for examples of how to use internal mechanisms to
implement new features. And please, always document new methods.

Sometimes you may want to implement OEM-specific code. For example, retrieving
firmware version information is not a part of standard IPMI, but some servers
are known to support it via custom OEM commands. If this is the case, follow
these steps:
- Add your generic retrieval function (stub) to the `OEMHandler` class in
  `aiohmi/ipmi/oem/generic.py`. And please, document its intent, parameters and
  expected return values.
- Implement the specific methods that your server supports in subdirectories in
  the `oem` folder (consider the `lenovo` submodule as an example). A OEM folder
  will contain at least one class inheriting from `OEMHandler`, and optionally
  helpers for running and parsing custom OEM commands.
- Register mapping policies in `aiohmi/ipmi/oem/lookup.py` so aiohmi knows how
  to associate a BMC session with the specific OEM code you implemented.

A good way of testing the new feature is using `bin/aiohmiutil`. Just add an
extension for the new feature you just implemented (as a new command) and call
it from the command line:
```
$ IPMIPASSWORD=passw0rd bin/aiohmiutil [BMC IP address] username my_new_feature_command
```
