import sys
import os
import signal
import subprocess
import time
import twill
import urllib2
import os.path
import re

CONFIG_FILE = os.path.expanduser('~/.config/lasso_integration.conf')
CONFIG = dict()

if os.path.exists(CONFIG_FILE):
    lines = open(CONFIG_FILE).read().splitlines()
    i = 1
    for line in lines:
        try:
            m = re.match('(\w*) = (.*)', line)
            CONFIG[m.groups()[0]] = m.groups()[1]
        except:
            print "Line", i, " of configuration file", CONFIG_FILE, "is invalid:", line
        i +=1

# Combine default and configuration file
AUTHENTIC_SRCDIR = CONFIG.get('AUTHENTIC_SRCDIR') or '/usr/local/src/authentic'
AUTHENTICCTL = CONFIG.get('AUTHENTICCTL') or '/usr/sbin/authenticctl.py'
AUTHENTIC_DATADIR = CONFIG.get('AUTHENTIC_DATADIR') or '/usr/share/authentic/'
LCSCTL = CONFIG.get('LCSCTL') or '/usr/sbin/lcsctl.py'
LCS_DATADIR = CONFIG.get('LCS_DATADIR') or '/usr/share/lcs/'
LASSO_BUILDDIR = os.environ.get('LASSO_BUILDDIR') or \
    CONFIG.get('LASSO_BUILDDIR') or \
    os.path.realpath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))

os.environ['LANG'] = 'C'
os.environ['LD_LIBRARY_PATH'] = os.path.join(LASSO_BUILDDIR, "lasso", ".libs") + ":" + \
        os.environ.get('LD_LIBRARY_PATH', '')
os.environ['PYTHONPATH'] = os.path.join(LASSO_BUILDDIR, "bindings", "python") + \
        ":" + os.path.join(LASSO_BUILDDIR, "bindings", "python", ".libs") + ":" + \
        os.environ.get('PYTHONPATH', '')

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

    silent = os.environ.get('NO_SILENT') is None
    twill.commands.reset_browser()
    twill.set_output(file('/dev/null', 'w'))
    base = []
    if os.environ.get('VALGRIND') is '1' and os.path.exists('/usr/bin/valgrind'):
        base = ['./valgrind-wrapper.sh', 'python']

    os.mkdir('/tmp/.tests')
    authentic_command = base + [AUTHENTICCTL, 'start',
            '--app-dir', '/tmp/.tests/authentictests',
            '--data-dir', AUTHENTIC_DATADIR,
            '--extra', os.path.join(AUTHENTIC_SRCDIR, 'extra', 'conformance'),
            '--port', '10001', '--http']
    if silent:
        authentic_command.append('--silent')
    sp = subprocess.Popen(authentic_command)
    pids.append(sp.pid)
    lcs_command = base + [LCSCTL, 'start',
            '--app-dir', '/tmp/.tests/lcstests',
            '--data-dir', LCS_DATADIR,
            '--port', '10002', '--http']
    if silent:
        lcs_command.append('--silent')
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

