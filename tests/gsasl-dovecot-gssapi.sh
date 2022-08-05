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

# Set up a local MIT Kerberos KDC, configure Dovecot, and then
# authenticate with GSS-API to the server using 'gsasl' as the client.

# No root privileges required, but listens on hard-coded ports 17643
# (KDC) and 17436 (dovecot).

# Environment variables GSASL specify tool to use, which may include
# valgrind/libtool or other profiling commands.

: ${GSASL=gsasl}

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

if ! command -v id || ! command -v hostname || ! command -v dovecot || ! command -v kinit || ! command -v kdb5_util || ! command -v kadmin.local || ! command -v krb5kdc; then
    echo SKIP: $0: Required tools missing...
    exit 77
fi

WORKDIR=$(mktemp -d)

trap 'set +e; test -f $WORKDIR/k/pid && kill `cat $WORKDIR/k/pid`; dovecot -c $WORKDIR/d/dovecot.conf stop; tail -v -n +0 $WORKDIR/out-* $WORKDIR/dovecot.log $WORKDIR/kdc.log; rm -r $WORKDIR/d $WORKDIR/b $WORKDIR/k $WORKDIR/*.log $WORKDIR/cc $WORKDIR/out-*; rmdir $WORKDIR' 0 INT QUIT ABRT PIPE TERM

: ${USER=`id -un`}
: ${GROUP=`id -gn`}

mkdir $WORKDIR/k  $WORKDIR/d

cat<<EOF > $WORKDIR/k/kdc.conf
[realms]
    GSASL.EXAMPLE = {
        database_name = $WORKDIR/k/principal
        key_stash_file = $WORKDIR/k/stash
        kdc_ports = 17643
        kdc_tcp_ports = 17643
        master_key_type = des3-hmac-sha1
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

cat <<EOF > $WORKDIR/d/dovecot.conf
protocols = imap

auth_gssapi_hostname = `hostname -f`

auth_krb5_keytab = $WORKDIR/d/dovecot.keytab

auth_verbose=yes
auth_debug=yes

disable_plaintext_auth=no
auth_mechanisms = gssapi
base_dir = $WORKDIR/b

passdb {
  driver = static
  args = password=pencil
}

log_path = $WORKDIR/dovecot.log

# https://wiki.dovecot.org/HowTo/Rootless

default_internal_user = $USER
default_internal_group = $GROUP

service anvil {
  chroot =
}
service imap-login {
  chroot =
}
service imap-login {
  inet_listener imap {
    port = 17436
  }
  inet_listener imaps {
    port = 0
  }
}
EOF

if test "$USER" = "root"; then
    cat <<EOF >> $WORKDIR/d/dovecot.conf
default_login_user = nobody
userdb {
  driver = static
  args = uid=4711 gid=4711 home=$WORKDIR mail=mbox:foo
}
EOF
else
    cat <<EOF >> $WORKDIR/d/dovecot.conf
default_login_user = $USER
userdb {
  driver = static
  args = uid=$USER gid=$GROUP home=$WORKDIR mail=mbox:foo
}
EOF
fi

export KRB5CCNAME=$WORKDIR/cc
export KRB5_CONFIG=$WORKDIR/k/krb5.conf
export KRB5_KDC_PROFILE=$WORKDIR/k

kdb5_util -P foo create -s
kadmin.local addprinc -randkey imap/`hostname -f`
kadmin.local addprinc -pw bar $USER
kadmin.local ktadd -k $WORKDIR/d/dovecot.keytab imap/`hostname -f`

krb5kdc -n -P $WORKDIR/k/pid &

i=0
while ! (ss -na || netstat -na) | grep 0.0.0.0:17643 | grep LISTEN; do
    i=`expr $i + 1`
    test "$i" = "10" && exit 1
    sleep 1
done

dovecot -c $WORKDIR/d/dovecot.conf

! $GSASL -m GSSAPI -d --no-starttls --imap `hostname -f` 17436 > $WORKDIR/out-err 2>&1

grep -q 'gss_init_sec_context' $WORKDIR/out-err

echo bar | kinit $USER

$GSASL -m GSSAPI -d --no-starttls --imap `hostname -f` 17436 > $WORKDIR/out-ok 2>&1

grep -q 'OK Logged in' $WORKDIR/out-ok

echo PASS: $0
exit 0
