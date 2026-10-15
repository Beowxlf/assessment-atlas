"""Unthreaded PTY child: establish its controlling terminal, then exec argv."""
import fcntl
import os
import sys
import termios

if __name__=='__main__':
    if not os.isatty(0) or os.geteuid()==0 or len(sys.argv)<2:
        raise SystemExit('An unprivileged controlling terminal and command are required.')
    fcntl.ioctl(0,termios.TIOCSCTTY,0)
    os.execvpe(sys.argv[1],sys.argv[1:],os.environ)
