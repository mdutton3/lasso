import sys
import os
import signal
import subprocess
import time
import twill
import urllib2

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

def waitforport(port, start):
    while True:
        if time.time() - start > 90:
            raise Exception('Servers did not start in 90 seconds!!')
        time.sleep(5)
        try:
            urllib2.urlopen('http://localhost:%s' % port)
        except urllib2.URLError:
            continue
        else:
            break

def setup():
    if not os.path.exists(AUTHENTIC_SRCDIR):
        print >> sys.stderr, 'Authentic source dir (%s) does not exist' % AUTHENTIC_SRCDIR
        print >> sys.stderr, 'Create it or edit tests/config.py to match your local installation'
        sys.exit(1)

    twill.commands.reset_browser()
    twill.set_output(file('/dev/null', 'w'))
    base = []
    if os.path.exists('/usr/bin/valgrind'):
        base = ['./valgrind-wrapper.sh', 'python']

    os.environ['PYTHONPATH'] = '../../bindings/python:../../bindings/python/.libs'
    os.mkdir('/tmp/.tests')
    authentic_command = base + [AUTHENTICCTL, 'start',
            '--app-dir', '/tmp/.tests/authentictests',
            '--data-dir', AUTHENTIC_DATADIR,
            '--extra', os.path.join(AUTHENTIC_SRCDIR, 'extra', 'conformance'),
            '--port', '10001', '--http', '--silent']
    print authentic_command
    sp = subprocess.Popen(authentic_command)
    pids.append(sp.pid)
    lcs_command = base + [LCSCTL, 'start',
            '--app-dir', '/tmp/.tests/lcstests',
            '--data-dir', LCS_DATADIR,
            '--port', '10002', '--http', '--silent']
    print lcs_command
    sp = subprocess.Popen(lcs_command)
    pids.append(sp.pid)

    # Wait for the daemons to load themselves
    starttime = time.time()
    waitforport(10001, starttime)
    waitforport(10002, starttime)


def teardown():
    for pid in pids:
        try:
            # valgrind seems to prefer SIGINT to SIGTERM
            os.kill(pid, signal.SIGINT)
        except OSError:
            print >> sys.stderr, 'failed to kill pid %s' % pid
    os.system('rm -rf /tmp/.tests/')

