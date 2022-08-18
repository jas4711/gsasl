#!/bin/sh

# Copyright (C) 2022 Simon Josefsson
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

set -e
set -u
set -x

# Configure MailUtils imap4d (which uses libgsasl), then authenticate
# to it using gsasl, for a couple of different CRAM-like mechanisms.

# No root privileges required, but listens on hard-coded port 19835.

# Environment variables GSASL and IMAP4D specify tools to use, which
# may include valgrind/libtool or other profiling commands.

: ${GSASL=gsasl}
: ${IMAP4D=imap4d}

if ! $GSASL --version 2> /dev/null | grep '^gsasl (GNU SASL'; then
    echo FAIL: $0: GNU SASL gsasl missing...
    exit 1
fi

export PATH=$PATH:/sbin:/usr/sbin

if ! $IMAP4D --version 2> /dev/null | grep '^imap4d (GNU Mailutils)'; then
    echo SKIP: $0: GNU Mailutils imap4d missing...
    exit 77
fi

if ! $IMAP4D --show-config-options 2> /dev/null | grep '^WITH_GSASL'; then
    echo SKIP: $0: No GNU SASL support in GNU Mailutils imap4d...
    exit 77
fi

if ! command -v ss && ! command -v netstat; then
    echo SKIP: $0: Required tools 'ss' or 'netstat' missing...
    exit 77
fi

WORKDIR=$(mktemp -d)

trap 'set +e; tail -v -n +0 $WORKDIR/out-*; test -f $WORKDIR/imap4d.pid && kill `cat $WORKDIR/imap4d.pid`; rm $WORKDIR/imap4d.pid $WORKDIR/mailutils.conf $WORKDIR/cram.txt $WORKDIR/out-*; rmdir $WORKDIR' 0 INT QUIT ABRT PIPE TERM

: ${USER=`whoami || id -un`}

cat <<EOF > $WORKDIR/cram.txt
$USER	foo
EOF

cat <<EOF > $WORKDIR/mailutils.conf
logging { syslog false;};
pidfile $WORKDIR/imap4d.pid;
gsasl {
 cram-passwd $WORKDIR/cram.txt;
};
server 127.0.0.1:19835 {
};
EOF

$IMAP4D --config-file=$WORKDIR/mailutils.conf --debug-level=4711 --daemon --foreground > $WORKDIR/out-imapd 2>&1 &

i=0
while ! (ss -na || netstat -na) | grep 127.0.0.1:19835 | grep LISTEN; do
    i=`expr $i + 1`
    test "$i" = "10" && exit 1
    sleep 1
done

! $GSASL -pbar -d -m CRAM-MD5 --verbose --imap 127.0.0.1 19835 > $WORKDIR/out-cram-md5-fail 2>&1

grep -q '^. NO AUTHENTICATE' $WORKDIR/out-cram-md5-fail

$GSASL -pfoo -d -m CRAM-MD5 --verbose --imap 127.0.0.1 19835 > $WORKDIR/out-cram-md5 2>&1

grep -q '^. OK AUTHENTICATE' $WORKDIR/out-cram-md5

$GSASL -pfoo -d -m DIGEST-MD5 --quality-of-protection=qop-auth --realm="" --verbose --imap 127.0.0.1 19835 > $WORKDIR/out-digest-md5 2>&1

grep -q '^. OK AUTHENTICATE' $WORKDIR/out-digest-md5

$GSASL -pfoo -d -m SCRAM-SHA-1 --verbose --imap 127.0.0.1 19835 > $WORKDIR/out-scram-sha-1 2>&1

grep -q '^. OK AUTHENTICATE' $WORKDIR/out-scram-sha-1

($GSASL -pfoo -d -m SCRAM-SHA-256 --verbose --imap 127.0.0.1 19835 > $WORKDIR/out-scram-sha-256 2>&1 \
     && grep -q '^. OK AUTHENTICATE' $WORKDIR/out-scram-sha-256) \
    || grep '^. NO AUTHENTICATE Authentication mechanism not supported' $WORKDIR/out-scram-sha-256

echo PASS: $0
exit 0
