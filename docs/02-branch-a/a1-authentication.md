## A.1 Defeat participant authentication, `DDS:Auth:PKI-DH` (T1 to T3)

A.1a yields an identity, A.1b yields the session keys.

```mermaid
graph LR
    A1["A.1 Defeat participant<br/>authentication [OR]"]
    A1 --> A1a["A.1a Become an authenticated<br/>participant [OR]"]
    A1 --> A1b["A.1b Recover the session<br/>keys [OR]"]

    A1a --> A11["A.1.1 dds.sec.auth.plugin unset,<br/>no handshake at all"]
    A1a --> A12["A.1.2 identity_ca shared with<br/>an untrusted or broader PKI"]
    A1a --> A13["A.1.3 identity_certificate reused<br/>across the whole fleet"]
    A1a --> A14["A.1.4 private_key world-readable,<br/>in the git repo or in the image"]
    A1a --> A15["A.1.5 password empty or stored<br/>in cleartext beside the key"]
    A1a --> A16["A.1.6 identity_crl not configured,<br/>revocation impossible"]
    A1a --> A19["A.1.9 Certificate validity unbounded<br/>or host clock unauthenticated"]

    A1b --> A17["A.1.7 preferred_key_agreement pinned<br/>to weak or legacy DH"]
    A1b --> A18["A.1.8 transmit_algorithms_as_legacy true,<br/>legacy identifier encoding"]
    A1a --> A110["A.1.10 Identity key below the<br/>minimum modulus or curve size"]
```

On a real robot `$KEYSTORE` is a copy, so A.1.4's modes only hold if it was fetched with `scp -p` or `rsync -a`. In the lab it is the target's volume mounted read-only, so modes are exact; owners print as `root` and the group as `rostarget`, the attacker's name for gid 1500.

Commands below use `$KEYSTORE`, `$ENVFILE`, `$RUN` and the rest; [the README](../../README.md) sets them.

### A.1.1 Auth plugin is PKI-DH

`Cons E1 E2 E3 E5` · `T T1` · `P P1` · `X X3`

**Parameter.** `dds.sec.auth.plugin`

**Misconfigured value.** Not set to `builtin.PKI-DH`

**Path to effect.** No mutual handshake, so any participant is accepted. Access-control grants become meaningless, because subject names are unverified.

```sh
xmllint --xpath '//*[local-name()="property"]' $XMLPROFILE | grep -A1 auth.plugin
```

Anything but `builtin.PKI-DH`, or absent, is the finding. Absent is A.0.5 as well.

**Cyclone DDS.** `<Authentication>` under `//CycloneDDS/Domain/Security`, with no `<Library>` or one naming `dds_security_auth`:

```sh
xmllint --xpath '//*[local-name()="Authentication"]/*[local-name()="Library"]/@path' $XMLPROFILE
```

No `<Authentication>` element is the finding. A `<Library>` naming anything else is a non-builtin plugin: record its path.

**Example**, the lab in its `all-open` posture:

```
XPath set is empty
```

**Zenoh.** `transport.link.tls.enable_mtls`, in the session and the router config:

```sh
zq $ZSESSION transport.link.tls.enable_mtls
zq $ZROUTER transport.link.tls.enable_mtls
```

`true` on both is clean. Anything else means peers are not authenticated: with no TLS any host joins, and with TLS but no mTLS any host joins without a certificate.

Then dial the router with no certificate. Only a certificate alert passes. The `tls-no-client-auth` preset produces this leaf.

```sh
sleep 2 | openssl s_client -connect $TARGET:7447 2>&1 | grep -E 'client certificate CA names|alert'
```

Under TLS 1.3 the alert arrives after the handshake, hence the `sleep`. `Acceptable client certificate CA names` followed by `tlsv13 alert certificate required` is clean. `No client certificate CA names sent` and no alert is the finding.

**Example**, the lab on Zenoh in its `tls-no-client-auth` posture:

```
No client certificate CA names sent
```

### A.1.2 Identity CA is dedicated

`Cons E1 E2 E3 E5` · `T T1` · `P P1` · `X X1`

**Parameter (`dds.sec.auth.builtin.PKI-DH.*`).** `identity_ca`

**Cyclone DDS.** `Authentication/IdentityCA`, plus any CA in `Authentication/TrustedCADirectory`, which widens the trust set the same way

**Misconfigured value.** Shared with a corporate or general-purpose CA, or a CA also used for VPN and web certificates

**Path to effect.** Any certificate from that CA authenticates as a robot participant. The attacker requests a normal certificate from IT and joins the robot domain.

No command. A process control: ask who operates the Identity CA, what else it signs, and what an issuance request has to satisfy. A CA that also issues VPN or web certificates is the finding, and no property of the certificate on the robot reveals that.

**Zenoh.** `transport.link.tls.root_ca_certificate`, which `generate_configs` points at the enclave's `identity_ca.cert.pem`. The same process question applies.

### A.1.3 Distinct identity per enclave

`Cons E1 E2 E3 E5` · `T T3` · `P P2` · `X X3`

**Parameter (`dds.sec.auth.builtin.PKI-DH.*`).** `identity_certificate`

**Cyclone DDS.** `Authentication/IdentityCertificate`

**Misconfigured value.** Shared identity certificate flashed into every robot image, same subject DN

**Path to effect.** Physical or remote access to **one** robot yields a credential valid on **all** robots, which is E5. Also breaks per-participant permissions.

```sh
for c in $KEYSTORE/enclaves/*/cert.pem; do openssl x509 -in "$c" -noout -subject; done |
    sort | uniq -c | sort -rn
```

A count above 1 on any subject DN is a shared identity within the robot. For the fleet question, run it against a second robot's keystore: an identical DN across two units is E5 and the highest-value finding in A.1.

**Example**, the lab in its `fleet-identity` posture:

```
      7 subject=CN = /robot
```

**Zenoh.** `transport.link.tls.connect_certificate` and `listen_certificate` in each node's config. Two more settings decide whether a distinct identity means anything: `verify_name_on_connect`, and the ACL subjects in A.3.13.

```sh
for f in $KEYSTORE/enclaves/*/zenoh_session.json5; do echo "$f: $(zq "$f" transport.link.tls.connect_certificate)"; done
zq $ZSESSION transport.link.tls.verify_name_on_connect
```

Two enclaves naming the same certificate is a shared identity. `false` on the second command is the finding, and `generate_configs` writes it: a peer is then accepted with any certificate the CA signed, whatever host it claims to be.

### A.1.4 Private key modes

`Cons E1 E2 E3 E5` · `T T3` · `P P2` · `X X3`

**Parameter (`dds.sec.auth.builtin.PKI-DH.*`).** `private_key`

**Cyclone DDS.** `Authentication/PrivateKey`. Cyclone also accepts the PEM inline as `data:,-----BEGIN...`, which makes the config file itself the key, so its mode is this leaf too

**Misconfigured value.** Mode `0644`, committed to the source repository, or in a public container layer

**Path to effect.** Credential theft, no exploitation required.

```sh
stat -c '%a %U %G %n' $KEYSTORE/enclaves/*/key.pem
```

Anything wider than `0440`, or owned by the ROS account rather than root, is the finding. From a copy, compare owners numerically (`%u` in place of `%U`) against `$RUN id -u $ROSUSER`. Owner-writable matters as much as world-readable: an account that can rewrite its own key can install one whose CA it controls.

**Example**, the lab in its `all-open` posture:

```
644 root rostarget /target-keystore/enclaves/robot/key.pem
```

**Zenoh.** `transport.link.tls.listen_private_key` and `connect_private_key`, which name the enclave's `key.pem`. The `stat` above applies unchanged, and also covers the router's key in `enclaves/zenohd/`.

### A.1.5 Key encrypted at rest

`Cons E1 E2 E3 E5` · `T T3` · `P P3` · `X X3`

**Parameter (`dds.sec.auth.builtin.PKI-DH.*`).** `password`

**Cyclone DDS.** `Authentication/Password`

**Misconfigured value.** Empty passphrase, or passphrase stored in the same XML profile or environment file as the key

**Path to effect.** Encryption at rest of the key is defeated, so theft of the configuration directory is enough.

```sh
head -2 $KEYSTORE/enclaves/*/key.pem
grep -rilE 'password|passphrase' $KEYSTORE
find $KEYSTORE -iname '*pass*' ! -name '*.p7s'
```

`BEGIN PRIVATE KEY` (PKCS#8, what `create_keystore` writes), `BEGIN EC PRIVATE KEY` and `BEGIN RSA PRIVATE KEY` (traditional PEM) are all unencrypted. A key is encrypted only as `BEGIN ENCRYPTED PRIVATE KEY`, or as traditional PEM whose second line is `Proc-Type: 4,ENCRYPTED`. An encrypted key whose passphrase sits in the rmw profile or in a `*.pass` file beside it, which the last two commands find, is the same finding wearing a hat. The remediation is a TPM or PKCS#11 token: sros2 cannot hand a passphrase to the RMW, so a passphrase alone stops every node from starting.

**Example**, the lab in its `all-open` posture:

```
-----BEGIN PRIVATE KEY-----
```

**Zenoh.** Zenoh's TLS configuration has no passphrase setting, so the key is unencrypted at rest by construction. The cleartext-secret question moves to user/password authentication:

```sh
zq $ZSESSION transport.auth.usrpwd
```

A `password` in the file, or a `dictionary_file` readable beyond its owner, is the same finding as a passphrase stored beside the key.

### A.1.6 CRL configured

`Cons E1 E2 E3 E5` · `T T2` · `P P3` · `X X3`

**Parameter (`dds.sec.auth.builtin.PKI-DH.*`).** `identity_crl`

**Cyclone DDS.** `Authentication/CRL`

**Misconfigured value.** Omitted, an optional parameter that `create_keystore` does not generate

**Path to effect.** A decommissioned robot, a returned RMA unit or a known-stolen key stays valid forever. There is no revocation path.

```sh
grep -A1 -i identity_crl $XMLPROFILE
openssl crl -in <the file it names> -noout -lastupdate -nextupdate
```

On Cyclone DDS, `xmllint --xpath '//*[local-name()="CRL"]/text()' $XMLPROFILE`.

Unconfigured is the finding, and it is the default. Configured but naming a file that does not exist, or one whose `nextUpdate` has passed, is the same finding: there is no revocation path either way. The profile names paths as the robot sees them: in the lab, read `/keystore/` as `$KEYSTORE/`. The lab's CRL is valid for 30 days from provisioning, and on Cyclone DDS the lab writes none whatever `TARGET_CRL` says, so this leaf is present in the Cyclone baseline.

**Example**, the lab in its `all-open` posture:

```
(no match)
```

**Zenoh.** No equivalent. Zenoh's TLS configuration has no CRL or OCSP setting, so rmw_zenoh has no revocation path and this leaf is present by construction. What remains is short certificate lifetimes (A.1.9) and a rehearsed rotation (A.4.5).

### A.1.7 Key agreement not legacy DH

`Cons E3` · `T T1` · `P P3` · `X X1`

**Parameter (`dds.sec.auth.builtin.PKI-DH.*`).** `preferred_key_agreement`

**Misconfigured value.** Absent, or set to `DH` or `DH+MODP-2048-256` instead of `ECDH+prime256v1-CEUM` or `AUTO`. Fast DDS 2.14 defaults to `DH` when the property is absent, so this is the unconfigured state and not a hand-forced one

**Path to effect.** The session keys come from the handshake's Diffie-Hellman exchange, and a fixed MODP group lowers its work factor. A passive tap can then decrypt captured traffic **retroactively** if that exchange is ever broken.

```sh
grep -A1 -i preferred_key_agreement $XMLPROFILE
```

Absent is the finding on Fast DDS 2.14, which falls back to `DH`. `AUTO` or `ECDH+prime256v1-CEUM` is clean.

**Cyclone DDS.** No equivalent setting, so on a Cyclone target this leaf is not applicable, which is not the same as passed. Cyclone picks the key agreement from its implementation, not from configuration. If it matters, decide it from a captured handshake.

**Example**, the lab's baseline with `TARGET_KEY_AGREEMENT=DH+MODP-2048-256` and `TARGET_LEGACY_ALGORITHMS=true` added to `preset.env`:

```
            <name>dds.sec.auth.builtin.PKI-DH.preferred_key_agreement</name>
            <value>DH+MODP-2048-256</value>
```

**Zenoh.** No equivalent setting. Zenoh links run TLS 1.3, which only negotiates ECDHE. Not applicable.

### A.1.8 Legacy algorithm advertisement off

`Cons E4` · `T T1` · `P P1` · `X X1`

**Parameter (`dds.sec.auth.builtin.PKI-DH.*`).** `transmit_algorithms_as_legacy`

**Misconfigured value.** `true`, where the default is `false`

**Path to effect.** Algorithm identifiers are transmitted in the non-standard legacy encoding. This changes how the identifiers are carried, not which algorithms the handshake negotiates, so no cipher suite is weakened. The effect is interoperability: standards-conformant peers may fail to match, which is E4.

```sh
grep -A1 -i transmit_algorithms_as_legacy $XMLPROFILE
```

Absent or `false` is clean, and is the default. `true` is the finding, and it is an interoperability effect rather than a weakened cipher suite.

**Cyclone DDS.** No equivalent setting, so on a Cyclone target this leaf is not applicable, which is not the same as passed.

**Example**, the lab's baseline with `TARGET_KEY_AGREEMENT=DH+MODP-2048-256` and `TARGET_LEGACY_ALGORITHMS=true` added to `preset.env`:

```
            <name>dds.sec.auth.builtin.PKI-DH.transmit_algorithms_as_legacy</name>
            <value>true</value>
```

**Zenoh.** No equivalent setting. Not applicable.

### A.1.9 Certificate lifetimes bounded

`Cons E4 E5` · `T T3` · `P P3` · `X X3`

**Parameter (`dds.sec.auth.builtin.PKI-DH.*`).** X.509 `notAfter` and host time

**Misconfigured value.** `create_keystore` issues 3650-day certificates, and expiry is unenforceable in any case where the host clock comes from unauthenticated NTP, see B.2.5

**Path to effect.** Stolen credentials never age out. Alternatively an attacker shifting the clock forces mass authentication failure, which is E4.

```sh
for c in $KEYSTORE/enclaves/*/cert.pem $KEYSTORE/public/*.cert.pem; do
    openssl x509 -in "$c" -noout -subject -dates
done
```

A `notAfter` more than a year out is the finding; `create_keystore` issues 3650 days. Read it with B.2.5: an expiry the host clock cannot be trusted to evaluate is not a control.

**Example**, the lab in its `all-open` posture:

```
subject=CN = /robot
notBefore=Sep  3 20:24:37 2026 GMT
notAfter=Aug 10 20:24:37 2126 GMT
```

**Zenoh.** Unchanged. mTLS uses the enclave certificates, plus the router's in `enclaves/zenohd/`.

### A.1.10 Key sizes

`Cons E1 E2 E3` · `T T1` · `P P1` · `X X1`

**Parameter (`dds.sec.auth.builtin.PKI-DH.*`).** X.509 key size

**Misconfigured value.** RSA below 2048 bits, or an EC curve below P-256

**Path to effect.** The identity key is within reach of offline attack, so an attacker impersonates that participant, or, if the CA's own key is the weak one, issues any identity. Rated `X1` because the work factor is high even when the key is undersized.

```sh
for c in $KEYSTORE/enclaves/*/cert.pem; do
    openssl x509 -in "$c" -noout -text | grep -E 'Public-Key|ASN1 OID'
done
```

RSA below 2048 bits, or a curve below P-256, is the finding.

**Example**, the lab in its `all-open` posture, excerpt:

```
                Public-Key: (1024 bit)
```

**Zenoh.** Unchanged, for the same certificates as A.1.9.

**Mitigations** 
- Use a dedicated offline Identity CA, distinct from all other PKI. 
- Issue one identity per enclave per robot, with `ros2 security create_enclave` run per node rather than per fleet. 
- Root-own the key files and grant the ROS account read through its group, `0440 root:<node group>` on the files and `0750` on the enclave directory. It reads its own credentials and can write none. 
- Treat ownership and modes as a deployment step. `ros2 security create_enclave` writes the keystore as the invoking user with default modes, and re-running it on the target undoes whatever was applied. 
- Where the hardware carries a TPM or a PKCS#11 token, hold the identity key there instead. `private_key` accepts a `pkcs11:` URI, but no `ros2 security` verb produces such a keystore. 
- Run a real CRL distribution and refresh process. 
- Set `preferred_key_agreement` explicitly to `ECDH+prime256v1-CEUM` or `AUTO`, since Fast DDS 2.14 falls back to `DH` when it is absent, and leave `transmit_algorithms_as_legacy` at `false`. 
- Keep certificate lifetimes in months with automated rotation, and enforce a minimum key size. 
- Use authenticated time, either NTS or a signed time source.
