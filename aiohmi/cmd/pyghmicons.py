# Copyright 2013 IBM Corporation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

""" A simple little script to exemplify/test ipmi.console module """

import fcntl
import os
import select
import sys
import termios
import threading
import tty

import six

from aiohmi.ipmi import console


def _doinput(sol):
    while True:
        select.select((sys.stdin,), (), (), 600)
        try:
            data = sys.stdin.read()
        except (IOError, OSError) as e:
            if e.errno == 11:
                continue
            raise

        sol.send_data(data)


def _print(data):
    bailout = False
    if not isinstance(data, six.string_types):
        bailout = True
        data = repr(data)
    sys.stdout.write(data)
    sys.stdout.flush()
    if bailout:
        raise Exception(data)


def main():
    tcattr = termios.tcgetattr(sys.stdin)
    newtcattr = tcattr
    # TODO(jbjohnso): add our exit handler
    newtcattr[-1][termios.VINTR] = 0
    newtcattr[-1][termios.VSUSP] = 0
    termios.tcsetattr(sys.stdin, termios.TCSADRAIN, newtcattr)

    tty.setraw(sys.stdin.fileno())
    currfl = fcntl.fcntl(sys.stdin.fileno(), fcntl.F_GETFL)
    fcntl.fcntl(sys.stdin.fileno(), fcntl.F_SETFL, currfl | os.O_NONBLOCK)

    try:
        if sys.argv[3] is None:
            passwd = os.environ['IPMIPASSWORD']
        else:
            passwd_file = sys.argv[3]
            with open(passwd_file, "r") as f:
                passwd = f.read()

        sol = console.Console(bmc=sys.argv[1], userid=sys.argv[2],
                              password=passwd, iohandler=_print, force=True)
        inputthread = threading.Thread(target=_doinput, args=(sol,))
        inputthread.daemon = True
        inputthread.start()
        sol.main_loop()

    except Exception:
        currfl = fcntl.fcntl(sys.stdin.fileno(), fcntl.F_GETFL)
        fcntl.fcntl(sys.stdin.fileno(), fcntl.F_SETFL, currfl ^ os.O_NONBLOCK)
        termios.tcsetattr(sys.stdin, termios.TCSANOW, tcattr)
        return 0


if __name__ == '__main__':
    sys.exit(main())
