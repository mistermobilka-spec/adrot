#!/bin/bash
# Provisions a throwaway OpenLDAP directory with an AD-shaped schema and seed data,
# then runs slapd in the foreground.
set -euo pipefail

echo "[testldap] provisioning ${LDAP_BASE}"

# Reconfigure slapd non-interactively. Debian's package normally asks these at
# install time; preseeding them lets the image build without a TTY.
cat >/tmp/slapd.preseed <<EOF
slapd slapd/no_configuration boolean false
slapd slapd/domain string ${LDAP_DOMAIN}
slapd shared/organization string ADRot Integration Test
slapd slapd/password1 password ${LDAP_ADMIN_PW}
slapd slapd/password2 password ${LDAP_ADMIN_PW}
slapd slapd/purge_database boolean true
slapd slapd/move_old_database boolean true
slapd slapd/backend select MDB
EOF
debconf-set-selections /tmp/slapd.preseed
rm -rf /var/lib/ldap/* /etc/ldap/slapd.d/*
dpkg-reconfigure -f noninteractive slapd >/dev/null 2>&1

# Start slapd locally so schema and data can be loaded over LDAP.
slapd -h "ldapi:/// ldap://127.0.0.1:389" -u openldap -g openldap
for _ in $(seq 1 30); do
  ldapsearch -Y EXTERNAL -H ldapi:/// -b cn=config -s base >/dev/null 2>&1 && break
  sleep 0.5
done

# Active Directory caps a single PAGE (MaxPageSize) and lets paging retrieve the rest.
# OpenLDAP instead caps the TOTAL entries a search may return, which paging cannot get
# past. Lift the cap so the fixture models AD's behaviour and the test actually
# exercises multi-page retrieval rather than just hitting a wall.
echo "[testldap] lifting the server size limit so paging behaves like AD"
ldapmodify -Y EXTERNAL -H ldapi:/// >/dev/null <<'EOF'
dn: cn=config
changetype: modify
replace: olcSizeLimit
olcSizeLimit: unlimited

dn: olcDatabase={1}mdb,cn=config
changetype: modify
replace: olcSizeLimit
olcSizeLimit: unlimited
EOF

echo "[testldap] loading AD-shaped schema"
# The schema is already in cn=config form, so it loads directly with no conversion
# step and no dependency on schema2ldif (which Debian bookworm does not package).
ldapadd -Y EXTERNAL -H ldapi:/// -f /seed/adrot-test-schema.ldif

echo "[testldap] seeding ${BULK_USERS} bulk users plus fixtures"
/seed/seed.sh > /tmp/seed.ldif
ldapadd -x -D "${LDAP_ADMIN_DN}" -w "${LDAP_ADMIN_PW}" -f /tmp/seed.ldif >/dev/null

COUNT=$(ldapsearch -x -H ldap://127.0.0.1:389 -b "${LDAP_BASE}" '(objectClass=*)' dn \
        | grep -c '^dn:' || true)
echo "[testldap] ready — ${COUNT} entries under ${LDAP_BASE}"

# Hand the foreground to slapd so the container stays up and Docker can supervise it.
kill "$(cat /var/run/slapd/slapd.pid)" 2>/dev/null || true
sleep 1
exec slapd -h "ldapi:/// ldap://0.0.0.0:389" -u openldap -g openldap -d 0
