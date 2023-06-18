# cscs-keygen

This repository contains a Python script `cscs-keygen` which can be
used to fetch SSH keys signed by CSCS' CA used for MFA selected
accounts.


## Install

To avoid messing with system-wide python distributions, I suggest
using [pipx](https://pypa.github.io/pipx/). If you rather use regular
`pip`, simply replace the `pipx` commands below with it.

For now, install the package directly from GitHub either via SSH

```bash
$ pipx install git+ssh://git@github.com/phdenzel/cscs-sshservice-cli.git@main
```

or via HTTPS

```bash
$ pipx install git+https://github.com/phdenzel/cscs-sshservice-cli.git@main
```

However, this package will eventually be available via PyPI.


## Usage

```console
usage: cscs-keygen [-h] [-u [USERNAME]] [-p [PASSWORD]] [-o [OTP]] [--passphrase [PASSPHRASE]] [--use_pass]
                   [--password_store PASSWORD_STORE] [--pass_name PASS_NAME] [--pass_otp PASS_OTP] [--no_otp]
                   [--use_macos_keyring] [-a API_URI] [-f KEY_NAME] [--use_passphrase] [-v] [--vvv]

options:
  -h, --help            show this help message and exit
  -u [USERNAME], --username [USERNAME], --user [USERNAME]
                        CSCS account username. (default: None)
  -p [PASSWORD], --password [PASSWORD], --pw [PASSWORD]
                        CSCS account password; recommendation: do not input the password directly, instead use '--
                        use_pass', '--macos_keyring', or simply wait for a secure password prompt during this program's
                        runtime. (default: None)
  -o [OTP], --otp [OTP]
                        CSCS OTP code. (default: None)
  --passphrase [PASSPHRASE]
                        Passphrase for the SSH key; recommendation: do not input the passphrase directly, instead wait for
                        a secure password prompt during this program's runtime. (default: None)
  --use_pass            Use the ZX2C4 UNIX password manager to fetch user authentication (see
                        https://www.passwordstore.org/). (default: False)
  --password_store PASSWORD_STORE
                        Location of the ZX2C4 UNIX password-store. (default: ~/.password-store)
  --pass_name PASS_NAME
                        Pass-name from the password-store. (default: cscs.ch)
  --pass_otp PASS_OTP   OTP pass-name from the password-store. (default: otp/cscs.ch)
  --no_otp              Do not fetch the OTP code from the password-store. (default: False)
  --use_macos_keyring   Use macOS' keyring to fetch user authentication. Not yet implemented. (default: False)
  -a API_URI, --api_uri API_URI
                        CSCS SSH key signing API identifier. (default: https://sshservice.cscs.ch/api/v1/auth/ssh-
                        keys/signed-key)
  -f KEY_NAME, --key_name KEY_NAME
                        Name of the SSH key file. (default: ~/.ssh/cscs_signed_key)
  --use_passphrase      Add a passphrase to the generated ssh keys. (default: False)
  -v, --verbose         Print info to stdout, except for passwords. (default: False)
  --vvv                 Strong verbosity mode, i.e. even parsed passwords will be printed to stdout. (default: False)
```

## Comments

This script is especially useful when using the [UNIX password manager](https://www.passwordstore.org/), i.e.

```bash
$ cscs-keygen --use_pass
```
see below for more details on getting started with the [UNIX password manager](https://www.passwordstore.org/).

In this mode, the script looks by default for `cscs.ch` in the
password-store to fetch username and password, and for `otp/cscs.sh`
to obtain the OTP code (provided it contains the otpauth URI).  This
way, there is no need to deal with prompts or manual user credential
inputs.

If the passwords have been saved in non-default locations in the
password-store, use the `--pass_name` and/or `--pass_otp` flags, e.g.
```bash
$ cscs-keygen --use_pass --pass_name some/other/location/cscs.ch --pass_otp some/other/otp/cscs.ch
```

## Further steps

Once the script has been executed and the signed SSH keys have been
saved, the keys can be used followingly:

1. Add the key to the SSH agent (provided you have a ssh-agent daemon running)
```bash
$ ssh-add -t 1d ~/.ssh/cscs_signed_key
```
2. Connect to the login node using the ssh-agent's CSCS keys:
```bash
$ ssh -A <USERNAME>@<CSCS-LOGIN-NODE>
```
Note, if the key is not added to the SSH agent as mentioned in step 1, then use:
```bash
$ ssh -i ~/.ssh/cscs_signed_key <CSCS-LOGIN-NODE>
```
or add an entry to your `~/.ssh/config`, e.g.
```config
Host cscs
  Hostname <CSCS-LOGIN-NODE>
  User <USERNAME>
  IdentityFile ~/.ssh/cscs_signed_key
```

## pass

Pass is a simple password management system designed for UNIX. It
saves passwords in `gpg`-encrypted files locally on your device, and
uses `git` for version control. Thus, it is easy to back up and sync
between devices using `git push` and `git pull` commands.

Furthermore, it is highly extensible and can work on all platforms
(linux, macOS, Windows), e.g. with the [QtPass
GUI](https://qtpass.org/). Especially relevant for this repository, I
recommend installing the OTP extension
[pass-otp](https://github.com/tadfisher/pass-otp).

#### Generate a GPG key
Before initializing your password-store, create a new gpg-id with the interactive command
```bash
gpg --gen-key
```
and follow the instructions given (you can use defaults on all prompts, continue with yes, and customize specifics using your user information).
If you're not familiar with GPG, I suggest reading up on it a bit more, it can come in handy in many more situations.

#### Initialize a password-store
Once, pass and all extensions have been installed, e.g. for Ubuntu
```bash
$ sudo apt-get install pass pass-otp
```
initiate your password-store with
```bash
$ pass init "<My personal GPG-ID>"
```
where `"<My personal GPG-ID>"` should be replaced with your newly created gpg-id.
You can find the gpg-id using 
```bash
$ gpg --list-keys
/home/user/.gnupg/pubring.gpg
------------------------------
pub   2048R/68214821 2022-12-05
uid                  First Middle Last Suffix <first.last@host.tld>
sub   2048R/36A6F06D 2022-12-05
```
In this case, `"<My personal GPG-ID>"` would be `"68214821"`.

Enable version control using
```bash
$ pass git init
```

#### Save passwords
Finally, we can add existing passwords to the password-store using
```bash
$ pass insert cscs.ch
```
or generate new passwords (of length 32) using
```bash
$ pass generate cscs.ch 32
```
You can also expand password information using your default editor for multiline mode, e.g.
```bash
$ pass edit cscs.ch
This-is-a-strong-password-of-L32
user: my-username
email: my-username@host.com
recovery-key: some-recovery-key
```

#### Accessing the passwords

You can easily retrieve the saved passwords using
```bash
$ pass cscs.ch
```
or save it (only the first line of your encrypted password file) to your clipboard with
```bash
$ pass cscs.ch -c
```

And for the times, you can't remember exactly where you saved it, use
```bash
$ pass find <some-pattern>
```

#### OTP

To retrieve an OTP URI from a QR code, save it to file, and use e.g. the [zbar](https://github.com/mchehab/zbar) tool for extraction
```bash
$ zbarimg -q --raw qr.png
otpauth://totp/CSCS:alice?secret=JBSWY3DPEHPK3PXP&digits=N&algorithm=SHA1&issuer=CSCS&period=N
```
zbar can be installed, e.g. with
```bash
$ sudo apt-get install zbar-tools
```

Finally, insert the OTP URI
```bash
$ pass otp insert otp/cscs.ch
Enter otpauth:// URI for otp/cscs.ch: otpauth://totp/CSCS:alice?secret=JBSWY3DPEHPK3PXP&digits=N&algorithm=SHA1&issuer=CSCS&period=N
```

To retrieve the OTP code, simply type
```bash
$ pass otp otp/cscs.ch
112233
```
