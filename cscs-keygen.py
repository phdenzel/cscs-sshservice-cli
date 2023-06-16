#!/usr/bin/env python
"""
This script sets the environment properly so that a user can access CSCS
login nodes via ssh.
   Copyright (C) 2023, ETH Zuerich, Switzerland

   This program is free software: you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation, version 3 of the License.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.

   AUTHORS Massimo Benini

Heavily modified and extended by
   AUTHORS Philipp Denzel
"""
import sys
import os
import json
from getpass import getpass
from pathlib import Path
from argparse import ArgumentParser, ArgumentDefaultsHelpFormatter
from argparse import Action, Namespace
from typing import Any
import requests
import passpy
import pyotp


class ArgPassPrompt(Action):
    """
    Prompt action for setting password input arguments in argparse.ArgumentParser
    """
    @staticmethod
    def prompt(key: str):
        match key.lower():
            case 'password':
                return getpass(f" {key.capitalize()}: ")
            case 'passphrase' | 'retype passphrase':
                return getpass(f" {key.capitalize()}: ")
            case _:
                return input(f" {key.capitalize()}: ")

    def __call__(self,
                 parser: ArgumentParser,
                 args: Namespace,
                 values: Any,
                 option_string: str = None):
        if values is None:
            values = self.prompt(self.dest)
        setattr(args, self.dest, values)


def parse_args():
    """
    Parse arguments from command-line and set defaults for all relevant arguments.
    """
    parser = ArgumentParser(formatter_class=ArgumentDefaultsHelpFormatter)
    # Direct user credential arguments
    parser.add_argument('-u', '--username', '--user', type=str, action=ArgPassPrompt, nargs='?',
                        help='CSCS account username.')
    parser.add_argument('-p', '--password', '--pw', type=str, action=ArgPassPrompt, nargs='?',
                        help='CSCS account password; recommendation: do not input the '
                        'password directly, instead use \'--use_pass\', \'--macos_keyring\', '
                        'or simply wait for a secure password prompt during this program\'s '
                        'runtime.')
    parser.add_argument('-o', '--otp', type=str, action=ArgPassPrompt, nargs='?',
                        help='CSCS OTP code.')
    parser.add_argument('--passphrase', type=str, action=ArgPassPrompt, nargs='?',
                        help='Passphrase for the SSH key; recommendation: do not input the '
                        'passphrase directly, instead wait for a secure password prompt during '
                        'this program\'s runtime.')
    # UNIX pass arguments
    parser.add_argument('--use_pass', action='store_true',
                        help='Use the ZX2C4 UNIX password manager to fetch user authentication '
                        '(see https://www.passwordstore.org/).')
    parser.add_argument('--password_store', type=str, default='~/.password-store',
                        help='Location of the ZX2C4 UNIX password-store.')
    parser.add_argument('--pass_name', type=str, default='cscs.ch',
                        help='Pass-name from the password-store.')
    parser.add_argument('--pass_otp', type=str, default='otp/cscs.ch',
                        help='OTP pass-name from the password-store.')
    parser.add_argument('--no_otp', action='store_true',
                        help='Do not fetch the OTP code from the password-store.')
    # macOS keyring arguments (TODO)
    parser.add_argument('--use_macos_keyring', action='store_true',
                        help='Use macOS\' keyring to fetch user authentication. '
                        'Not yet implemented.')
    # ssh-keygen arguments
    parser.add_argument('-a', '--api_uri', type=str,
                        default='https://sshservice.cscs.ch/api/v1/auth/ssh-keys/signed-key',
                        help='CSCS SSH key signing API identifier.')
    parser.add_argument('-i', '--key_name', type=str, default='~/.ssh/cscs_signed_key',
                        help='Name of the SSH key file.')
    parser.add_argument('--use_passphrase', action='store_true',
                        help='Add a passphrase to the generated ssh keys.')
    # misc arguments
    parser.add_argument('-v', '--verbose', action='store_true',
                        help='Print info to stdout, except for passwords.')
    parser.add_argument('--vvv', action='store_true',
                        help='Strong verbosity mode, i.e. even parsed passwords '
                        'will be printed to stdout.')
    args = parser.parse_args()
    if args.vvv:
        args.verbose = args.vvv
    return args


def print_args(args: Namespace):
    """
    Prettily formatted parsed arguments
    """
    dargs = vars(args)
    force_v = dargs.get('vvv', False)
    print('# Arguments '+'-'*48)
    for dest, value in dargs.items():
        if not force_v and dest in ['password', 'passphrase', 'otp']:
            value = '*'*len(value) if value else None
        print(f"  {dest:26}{value}")
    print('-'*60)


def fetch_credentials_zx2c4pass(args: Namespace):
    """
    Fetch user and OTP credentials from UNIX pass
    """
    store = passpy.Store(store_dir=args.password_store)
    # user credentials
    pass_content = store.get_key(args.pass_name).split('\n')
    if args.password is None:
        args.password = pass_content[0].strip()
    if args.username is None:
        for line in pass_content[1:]:
            fields = line.split(':')
            f1 = fields[0].lower()
            if f1 in ['user', 'username', 'login']:
                args.username = fields[1].strip()
    # otp credentials
    otp_content = store.get_key(args.pass_otp)
    if args.otp is None and not args.no_otp:
        args.otp = pyotp.parse_uri(otp_content).now()
    return args


def fetch_credentials_macoskeyring(args: Namespace):
    """
    Fetch user credentials from macOS keyring
    """
    return NotImplemented


def get_user_credentials(args: Namespace):
    """
    Fetch user credentials depending on parsed configuration
    """
    if args.use_pass:
        args = fetch_credentials_zx2c4pass(args)
    elif args.use_macos_keyring:
        args = fetch_credentials_macoskeyring(args)
    if args.username is None:
        args.username = ArgPassPrompt.prompt('username')
    if args.password is None:
        args.password = ArgPassPrompt.prompt('password')
    if args.otp is None:
        args.otp = ArgPassPrompt.prompt('one-time pass')
    return args


def get_keys(args: Namespace):
    """
    Request signed SSH keys from the CSCS API
    """
    headers = {'Content-Type': 'application/json', 'Accept':'application/json'}
    data = {"username": args.username, "password": args.password, "otp": args.otp}
    try:
        resp = requests.post(args.api_uri, data=json.dumps(data), headers=headers, verify=True)
        resp.raise_for_status()
    except requests.exceptions.RequestException as e:
        try:
            d_payload = e.response.json()
        except:
            raise SystemExit(e)
        if "payload" in d_payload and "message" in d_payload["payload"]:
            print(f"Error: {d_payload['payload']['message']}")
        raise SystemExit(e)
    else:
        public_key = resp.json()['public']
        if not public_key:
            sys.exit("Error: Unable to fetch public key.")
        private_key = resp.json()['private']
        if not private_key:
            sys.exit("Error: Unable to fetch private key.")
        return public_key, private_key


def save_keys(public, private, args: Namespace = None):
    """
    Save requested SSH keys to files in specified location
    """
    key = Path(args.key_name).expanduser()
    key_pub = key.with_suffix('.pub')
    if not public or not private:
        sys.exit("Error: invalid keys.")
    # write public key
    if args.verbose:
        print(f"Writing public key to {str(key_pub)}")
    try:
        with key_pub.open('w') as f:
            f.write(public)
        key_pub.chmod(0o644)
    except IOError as err:
        sys.exit('Error: Writing public key to file failed.', err)
    except Exception as ex:
        sys.exit('Error: Cannot change permissions of the public key.', ex)
    # write private key
    if args.verbose:
        print(f"Writing private key to {str(key)}")
    try:
        with key.open('w') as f:
            f.write(private)
        key.chmod(0o600)
    except IOError as err:
        sys.exit('Error: Writing private key to file failed.', err)
    except Exception as ex:
        sys.exit('Error: cannot change permissions of the private key.', ex)


def set_passphrase(args: Namespace):
    """
    Add a passphrase to the keys (recommended)
    """
    key = Path(args.key_name).expanduser()
    key_pub = key.with_suffix('.pub')
    if args.passphrase is None and args.use_passphrase:
        passphrase_1 = 0
        count = 3
        while count:
            args.passphrase = ArgPassPrompt.prompt('passphrase')
            passphrase_1 = args.passphrase
            args.passphrase = ArgPassPrompt.prompt('retype passphrase')
            if passphrase_1 == args.passphrase:
                break
            else:
                count -= 1
                print(f"Passphrase did not match. Retry ({count}).")
                if count == 0:
                    args.passphrase = None
    if args.passphrase is not None:  # at this point the passphrase is verified
        if args.verbose and not args.vvv:
            print(f"{'Setting passphrase:':26}{'*'*len(args.passphrase)}")
        elif args.vvv:
            print(f"{'Setting passphrase:':26}{args.passphrase}")
        os.system(f'ssh-keygen -p -N "{args.passphrase}" -f {args.key_name}')


def gen_dummy_key(args: Namespace):
    """
    For testing... generate dummy SSH keys
    """
    key = Path(args.key_name).expanduser()
    key_pub = key.with_suffix('.pub')
    os.system(f'ssh-keygen -t ed25519 -f {args.key_name} -N "" -q')
    private = key.open('r').read()
    public = key_pub.open('r').read()
    return public, private


def main():
    """
    Parse arguments, fetch SSH keys from the CSCS API, and securely save them in files
    """
    # parse arguments
    args = parse_args()
    args = get_user_credentials(args)
    if args.verbose:
        print('CSCS SSH keygen')
        print_args(args)
    # fetch signed SSH keys from CSCS API
    public, private = get_keys(args)
    #public, private = gen_dummy_key(args)
    # save keys in files and set permissions
    save_keys(public, private, args=args)
    set_passphrase(args)
    # optional instructions
    message = f"""
    Further steps:

    1. Add the key to the SSH agent
      $ ssh-add -t 1d {args.key_name}

    2. Connect to the login node using CSCS keys:
      $ ssh -A {args.username}@<CSCS-LOGIN-NODE>

    Note, if the key is not added to the SSH agent as mentioned in step 1, then use:
      $ ssh -i {args.key_name} <CSCS-LOGIN-NODE>
    """
    if args.verbose:
        print(message)


if __name__ == "__main__":
    main()
