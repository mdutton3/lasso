import sys
import os
import signal
import subprocess
import time
import twill

AUTHENTIC_SRCDIR = '/usr/local/src/authentic'
AUTHENTICCTL = '/usr/sbin/authenticctl.py'
AUTHENTIC_DATA_DIR = '/usr/share/authentic/'
LCSCTL = '/usr/sbin/lcsctl.py'
LCS_DATADIR = '/usr/share/lcs/'

try:
    from config import *
except ImportError:
    pass

pids = []

def setup():
    if not os.path.exists(AUTHENTIC_SRCDIR):
        print >> sys.stderr, 'Authentic source dir (%s) does not exist' % AUTHENTIC_SRCDIR
        print >> sys.stderr, 'Create it or edit tests/config.py to match your local installation'
        sys.exit(1)

    os.mkdir('/tmp/.tests')
    sp = subprocess.Popen([AUTHENTICCTL, 'start',
            '--app-dir', '/tmp/.tests/authentictests',
            '--data-dir', AUTHENTIC_DATADIR,
            '--extra', os.path.join(AUTHENTIC_SRCDIR, 'extra', 'conformance'),
            '--port', '10001', '--http', '--silent'])
    pids.append(sp.pid)
    sp = subprocess.Popen([LCSCTL, 'start',
            '--app-dir', '/tmp/.tests/lcstests',
            '--data-dir', LCS_DATADIR,
            '--port', '10002', '--http', '--silent'])
    pids.append(sp.pid)

    time.sleep(2) # let process bind ports

    twill.commands.reset_browser()
    twill.set_output(file('/dev/null', 'w'))


def teardown():
    for pid in pids:
        os.kill(pid, signal.SIGTERM)
    os.system('rm -rf /tmp/.tests/')

