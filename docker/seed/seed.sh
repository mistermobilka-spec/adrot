#!/bin/bash
# Generates the seed LDIF for the ADRot integration test directory.
#
# Emits deliberately more than 500 user entries so that the paged-search code in
# Invoke-ADRotLdapSearch is genuinely exercised. A test directory smaller than one
# page would pass even if paging were completely broken — which is exactly the bug
# that silently truncates a real 40,000-object domain.
set -euo pipefail

BASE="${LDAP_BASE:-dc=adrot,dc=test}"
BULK_USERS="${BULK_USERS:-600}"

cat <<EOF
dn: ou=Staff,${BASE}
objectClass: organizationalUnit
ou: Staff

dn: ou=Servers,${BASE}
objectClass: organizationalUnit
ou: Servers

dn: ou=Groups,${BASE}
objectClass: organizationalUnit
ou: Groups

dn: cn=svc-sql,ou=Staff,${BASE}
objectClass: inetOrgPerson
objectClass: adRotPrincipal
cn: svc-sql
sn: sql
sAMAccountName: svc-sql
objectCategory: person
userAccountControl: 66048
pwdLastSet: 133000000000000000
lastLogonTimestamp: 133700000000000000
adminCount: 0
servicePrincipalName: MSSQLSvc/sql01.adrot.test:1433

dn: cn=asrep-victim,ou=Staff,${BASE}
objectClass: inetOrgPerson
objectClass: adRotPrincipal
cn: asrep-victim
sn: victim
sAMAccountName: asrep-victim
objectCategory: person
userAccountControl: 4194816
pwdLastSet: 133000000000000000
lastLogonTimestamp: 133700000000000000
adminCount: 0

dn: cn=kiosk,ou=Staff,${BASE}
objectClass: inetOrgPerson
objectClass: adRotPrincipal
cn: kiosk
sn: kiosk
sAMAccountName: kiosk
objectCategory: person
userAccountControl: 544
pwdLastSet: 133000000000000000
lastLogonTimestamp: 133700000000000000
adminCount: 0

dn: cn=admin-jdoe,ou=Staff,${BASE}
objectClass: inetOrgPerson
objectClass: adRotPrincipal
cn: admin-jdoe
sn: jdoe
sAMAccountName: admin-jdoe
objectCategory: person
userAccountControl: 512
pwdLastSet: 133700000000000000
lastLogonTimestamp: 133700000000000000
adminCount: 1

dn: cn=OLDAPP01,ou=Servers,${BASE}
objectClass: device
objectClass: adRotPrincipal
cn: OLDAPP01
sAMAccountName: OLDAPP01\$
objectCategory: computer
userAccountControl: 4096
operatingSystem: Windows Server 2008 R2 Standard
operatingSystemVersion: 6.1 (7601)
lastLogonTimestamp: 133700000000000000

dn: cn=PRINT01,ou=Servers,${BASE}
objectClass: device
objectClass: adRotPrincipal
cn: PRINT01
sAMAccountName: PRINT01\$
objectCategory: computer
userAccountControl: 528384
operatingSystem: Windows Server 2019 Standard
operatingSystemVersion: 10.0 (17763)
lastLogonTimestamp: 133700000000000000

dn: cn=Domain Admins,ou=Groups,${BASE}
objectClass: groupOfNames
objectClass: adRotPrincipal
cn: Domain Admins
sAMAccountName: Domain Admins
objectCategory: group
member: cn=admin-jdoe,ou=Staff,${BASE}
EOF

# objectSid is an OCTET STRING, so it must be base64-encoded in LDIF. This value
# decodes to S-1-5-21-...-512 (Domain Admins), which is what lets the integration
# test prove ConvertFrom-ADRotLdapSid works on a real binary attribute off the wire.
printf 'objectSid:: %s\n\n' "$(printf '\x01\x05\x00\x00\x00\x00\x00\x05\x15\x00\x00\x00\x00\x01\x02\x03\x00\x02\x03\x04\x00\x03\x04\x05\x00\x02\x00\x00' | base64 -w0)"

# Bulk users to force multi-page searches.
for i in $(seq 1 "${BULK_USERS}"); do
cat <<EOF
dn: cn=bulk${i},ou=Staff,${BASE}
objectClass: inetOrgPerson
objectClass: adRotPrincipal
cn: bulk${i}
sn: bulk
sAMAccountName: bulk${i}
objectCategory: person
userAccountControl: 512
pwdLastSet: 133700000000000000
lastLogonTimestamp: 133700000000000000
adminCount: 0

EOF
done
