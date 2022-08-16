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

# Set up a local MIT Kerberos KDC, configure MailUtils imap4d (which
# uses libgsasl), and then authenticate with GS2-KRB5 and GSSAPI to
# the server using 'gsasl' as the client.

# No root privileges required, but listens on hard-coded ports 17643
# (KDC) and 19835 (imap4d).

# Environment variables GSASL and IMAP4D specify tools to use, which
# may include valgrind/libtool or other profiling commands.

: ${GSASL=gsasl}
: ${IMAP4D=imap4d}

if ! $GSASL --version 2> /dev/null | grep '^gsasl (GNU SASL'; then
    echo FAIL: $0: GNU SASL gsasl missing...
    exit 1
fi

if ! $GSASL --client-mechanisms 2>&1 | grep ' GSSAPI '; then
    echo SKIP: $0: No GSSAPI support detected...
    exit 77
fi

if test "${GNUGSS:-no}" = yes; then
    echo SKIP: $0: Not ported to Shishi/GSS ccache yet...
    exit 77
fi

export PATH=$PATH:/sbin:/usr/sbin

if ! command -v ss && ! command -v netstat; then
    echo SKIP: $0: Required tools 'ss' or 'netstat' missing...
    exit 77
fi

if ! $IMAP4D --version 2> /dev/null | grep '^imap4d (GNU Mailutils)'; then
    echo SKIP: $0: GNU Mailutils imap4d missing...
    exit 77
fi

if ! command -v id || ! command -v hostname || ! command -v kinit || ! command -v kdb5_util || ! command -v kadmin.local || ! command -v krb5kdc; then
    echo SKIP: $0: Required tools missing...
    exit 77
fi

WORKDIR=$(mktemp -d)

trap 'set +e; test -f $WORKDIR/k/pid && kill `cat $WORKDIR/k/pid`; test -f $WORKDIR/imap4d.pid && kill `cat $WORKDIR/imap4d.pid`; tail -v -n +0 $WORKDIR/out-* $WORKDIR/kdc.log; rm -r $WORKDIR/imap4d.pid $WORKDIR/mailutils.conf $WORKDIR/k $WORKDIR/*.log $WORKDIR/cc $WORKDIR/kt $WORKDIR/out-*; rmdir $WORKDIR' 0 INT QUIT ABRT PIPE TERM

: ${USER=`id -un`}
: ${GROUP=`id -gn`}

mkdir $WORKDIR/k $WORKDIR/k/etc

cat<<EOF > $WORKDIR/k/kdc.conf
[realms]
    GSASL.EXAMPLE = {
        database_name = $WORKDIR/k/principal
        key_stash_file = $WORKDIR/k/stash
        kdc_ports = 17643
        kdc_tcp_ports = 17643
        default_principal_flags = +preauth
    }
[logging]
   kdc = FILE:$WORKDIR/kdc.log
EOF

cat<<EOF > $WORKDIR/k/krb5.conf
[libdefaults]
	default_realm = GSASL.EXAMPLE

[domain_realm]
	.`hostname -d` = GSASL.EXAMPLE

[realms]
	GSASL.EXAMPLE = {
		kdc = `hostname -f`:17643
	}
EOF

export KRB5CCNAME=$WORKDIR/cc
export KRB5_CONFIG=$WORKDIR/k/krb5.conf
export KRB5_KDC_PROFILE=$WORKDIR/k
export KRB5_KTNAME=$WORKDIR/kt

kdb5_util -P foo create -s
kadmin.local addprinc -randkey imap/`hostname -f`
kadmin.local addprinc -pw bar $USER
kadmin.local ktadd -k $KRB5_KTNAME imap/`hostname -f`

krb5kdc -n -P $WORKDIR/k/pid &

i=0
while ! (ss -na || netstat -na) | grep 0.0.0.0:17643 | grep LISTEN; do
    i=`expr $i + 1`
    test "$i" = "10" && exit 1
    sleep 1
done

cat <<EOF > $WORKDIR/mailutils.conf
logging { syslog false;};
pidfile $WORKDIR/imap4d.pid;
server 0.0.0.0:19835 {
};
EOF

$IMAP4D --config-file=$WORKDIR/mailutils.conf --debug-level=4711 --daemon --foreground > $WORKDIR/out-imapd 2>&1 &

i=0
while ! (ss -na || netstat -na) | grep 0.0.0.0:19835 | grep LISTEN; do
    i=`expr $i + 1`
    test "$i" = "10" && exit 1
    sleep 1
done

! $GSASL -m GSSAPI -d --no-starttls --imap `hostname -f` 19835 > $WORKDIR/out-err 2>&1

grep -q 'gss_init_sec_context' $WORKDIR/out-err

echo bar | kinit $USER

$GSASL -m GS2-KRB5 -d --no-starttls --imap `hostname -f` 19835 -z $USER > $WORKDIR/out-gs2krb5 2>&1

grep -q '^. OK AUTHENTICATE' $WORKDIR/out-gs2krb5

$GSASL -m GSSAPI -d --no-starttls --imap `hostname -f` 19835 -z $USER > $WORKDIR/out-gssapi 2>&1

grep -q '^. OK AUTHENTICATE' $WORKDIR/out-gssapi

echo PASS: $0
exit 0
