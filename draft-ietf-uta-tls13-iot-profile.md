---
title: TLS/DTLS 1.3 Profiles for the Internet of Things
abbrev: TLS/DTLS 1.3 IoT Profiles
docname: draft-ietf-uta-tls13-iot-profile-latest
category: std
updates: 7925
consensus: true

ipr: trust200902
area: Security
workgroup: UTA
keyword: Internet-Draft

stand_alone: yes
pi:
  rfcedstyle: yes
  toc: yes
  tocindent: yes
  sortrefs: yes
  symrefs: yes
  strict: yes
  comments: yes
  inline: yes
  text-list-symbols: o-*+
  compact: yes
  subcompact: yes
  consensus: false

author:
 -
    ins: H. Tschofenig
    name: Hannes Tschofenig
    organization: "Arm Limited"
    email: Hannes.Tschofenig@gmx.net

 -
    ins: T. Fossati
    name: Thomas Fossati
    organization: "Arm Limited"
    email: Thomas.Fossati@arm.com

--- abstract

This document is a companion to RFC 7925 and defines TLS/DTLS 1.3 profiles for
Internet of Things devices.  It also updates RFC 7925 with regards to the X.509
certificate profile.

--- middle

# Introduction

This document defines a profile of DTLS 1.3 {{!I-D.ietf-tls-dtls13}} and TLS
1.3 {{!RFC8446}} that offers communication security services for IoT
applications and is reasonably implementable on many constrained devices.
Profile thereby means that available configuration options and protocol
extensions are utilized to best support the IoT environment.

For IoT profiles using TLS/DTLS 1.2 please consult {{!RFC7925}}. This document
re-uses the communication pattern defined in {{!RFC7925}} and makes IoT-domain
specific recommendations for version 1.3 (where necessary).

TLS 1.3 has been re-designed and several previously defined extensions are not
applicable to the new version of TLS/DTLS anymore. This clean-up also
simplifies this document.  Furthermore, many outdated ciphersuites have been
omitted from the TLS/DTLS 1.3 specification.

## Conventions and Terminology

{::boilerplate bcp14}

# Credential Types

In accordance with the recommendations in {{!RFC7925}}, a compliant
implementation MUST implement TLS_AES_128_CCM_8_SHA256. It SHOULD implement
TLS_CHACHA20_POLY1305_SHA256.

Pre-shared key based authentication is integrated into the main TLS/DTLS 1.3
specification and has been harmonized with session resumption.

A compliant implementation supporting authentication based on certificates and
raw public keys MUST support digital signatures with ecdsa_secp256r1_sha256. A
compliant implementation MUST support the key exchange with secp256r1 (NIST
P-256) and SHOULD support key exchange with X25519.

A plain PSK-based TLS/DTLS client or server MUST implement the following
extensions:

* supported_versions
* cookie
* server_name
* pre_shared_key
* psk_key_exchange_modes

For TLS/DTLS clients and servers implementing raw public keys and/or
certificates the guidance for mandatory-to-implement extensions described in
Section 9.2 of {{!RFC8446}} MUST be followed.

# Error Handling

TLS 1.3 simplified the Alert protocol but the underlying challenge in an
embedded context remains unchanged, namely what should an IoT device do when it
encounters an error situation. The classical approach used in a desktop
environment where the user is prompted is often not applicable with unattended
devices. Hence, it is more important for a developer to find out from which
error cases a device can recover from.

# Session Resumption

TLS 1.3 has built-in support for session resumption by utilizing PSK-based
credentials established in an earlier exchange.

# Compression

TLS 1.3 does not have support for compression.

# Perfect Forward Secrecy

TLS 1.3 allows the use of PFS with all ciphersuites since the support for it is
negotiated independently.

# Keep-Alive

The discussion in Section 10 of {{!RFC7925}} is applicable.

# Timeouts

The recommendation in Section 11 of {{!RFC7925}} is applicable. In particular
this document RECOMMENDED to use an initial timer value of 9 seconds with
exponential back off up to no less then 60 seconds.

Question: DTLS 1.3 now offers per-record retransmission and therefore
introduces much less congestion risk associated with spurious retransmissions.
Hence, should we relax the 9s initial timeout?

# Random Number Generation

The discussion in Section 12 of {{!RFC7925}} is applicable with one exception:
the ClientHello and the ServerHello messages in TLS 1.3 do not contain
gmt_unix_time component anymore.

# Server Name Indication (SNI)

This specification mandates the implementation of the SNI extension. Where
privacy requirements require it, the encrypted SNI extension
{{?I-D.ietf-tls-esni}} prevents an on-path attacker to determine the domain
name the client is trying to connect to. Note, however, that the extension is
still at an experimental state.

# Maximum Fragment Length Negotiation

The Maximum Fragment Length Negotiation (MFL) extension has been superseded by
the Record Size Limit (RSL) extension {{!RFC8449}}. Implementations in
compliance with this specification MUST implement the RSL extension and SHOULD
use it to indicate their RAM limitations.

# Crypto Agility

The recommendations in Section 19 of {{!RFC7925}} are applicable.

# Key Length Recommendations

The recommendations in Section 20 of {{!RFC7925}} are applicable.

# 0-RTT Data

When clients and servers share a PSK, TLS/DTLS 1.3 allows clients to send data
on the first flight ("early data"). This features reduces communication setup
latency but requires application layer protocols to define its use with the
0-RTT data functionality.

For HTTP this functionality is described in {{!RFC8470}}. This document
specifies the application profile for CoAP, which follows the design of
{{!RFC8470}}.

For a given request, the level of tolerance to replay risk is specific to the
resource it operates upon (and therefore only known to the origin server).  In
general, if processing a request does not have state-changing side effects, the
consequences of replay are not significant. The server can choose whether it
will process early data before the TLS handshake completes.

It is RECOMMENDED that origin servers allow resources to explicitly configure
whether early data is appropriate in requests.

This specification specifies the Early-Data option, which indicates that the
request has been conveyed in early data and that a client understands the 4.25
(Too Early) status code. The semantic follows {{!RFC8470}}.

~~~
+-----+---+---+---+---+-------------+--------+--------+---------+---+
| No. | C | U | N | R | Name        | Format | Length | Default | E |
+-----+---+---+---+---+-------------+--------+--------+---------+---+
| TBD | x |   |   |   | Early-Data  | empty  | 0      | (none)  | x |
+-----+---+---+---+---+-------------+--------+--------+---------+---+

        C=Critical, U=Unsafe, N=NoCacheKey, R=Repeatable,
        E=Encrypt and Integrity Protect (when using OSCORE)
~~~
{: #early-data-figure title="Early-Data Option"}

# Certificate Profile

This section contains updates and clarifications to the certificate profile
defined in {{!RFC7925}}.  The content of Table 1 of {{!RFC7925}} has been
split by certificate "type" in order to clarify exactly what requirements and
recommendations apply to which entity in the PKI hierarchy.

## All Certificates

### Version

Certificates MUST be of type X.509 v3.

### Serial Number

CAs SHALL generate non-sequential Certificate serial numbers greater than zero
(0) containing at least 64 bits of output from a CSPRNG (cryptographically
secure pseudo-random number generator).

### Signature

The signature MUST be ecdsa-with-SHA256 or stronger {{!RFC5758}}.

### Issuer

Contains the DN of the issuing CA.

### Validity

No maximum validity period is mandated.

### subjectPublicKeyInfo

The SubjectPublicKeyInfo structure indicates the algorithm and any associated
parameters for the ECC public key.  This  profile uses the id-ecPublicKey
algorithm  identifier for ECDSA signature keys, as   defined and specified in
{{!RFC5480}}.

## Root CA Certificate

* basicConstraints MUST be present and MUST be marked critical.  The cA field
  MUST be set true.  The pathLenConstraint field SHOULD NOT be present.

* keyUsage MUST be present and MUST be marked critical.  Bit position for
  keyCertSign MUST be set.

* extendedKeyUsage MUST NOT be present.

## Intermediate CA Certificate

* basicConstraints MUST be present and MUST be marked critical.  The cA field
  MUST be set true.  The pathLenConstraint field MAY be present.

* keyUsage MUST be present and MUST be marked critical.  Bit position for
  keyCertSign MUST be set.

* extendedKeyUsage MUST NOT be present.

## End Entity Certificate

* extendedKeyUsage MUST be present and contain at least one of
  id-kp-serverAuth or id-kp-clientAuth.

* keyUsage MAY be present and contain one of digitalSignature or
  keyAgreement.

* Domain names MUST NOT be encoded in the subject commonName, instead they
  MUST be encoded in a subjectAltName of type DNS-ID.  Domain names MUST NOT
  contain wildcard (`*`) characters.  subjectAltName MUST NOT contain multiple
  names.

### Client Certificate Subject

The requirement in Section 4.4.2 of {{!RFC7925}} to only use EUI-64 for client
certificates is lifted.

If the EUI-64 format is used to identify the subject of a client certificate,
it MUST be encoded in a subjectAltName of type DNS-ID as a string of the form
`HH-HH-HH-HH-HH-HH-HH-HH` where 'H' is one of the symbols '0'-'9' or 'A'-'F'.

# Certificate Revocation Checks

The considerations in Section 4.4.3 of {{!RFC7925}} hold. 

Since the publication of 
RFC 7925 the need for firmware update mechanisms has been reinforced and the work
on standardizing a secure and interoperable firmware update mechanism has made 
substantial progress, see {{?I-D.ietf-suit-architecture}}. RFC 7925 recommends to use 
a software / firmware update mechanism to provision devices with new trust anchors. 

The use of device management protocols for IoT devices, which often include an onboarding 
or bootstrapping mechanism, has also seen considerable uptake in deployed devices and 
these protocols, some of which are standardized, allow provision of certificates on a 
regular basis. This enables a deployment model where IoT device utilize end-entity 
certificates with shorter lifetime making certificate revocation protocols, like OCSP 
and CRLs, less relevant.

Hence, instead of performing certificate revocation checks on the IoT device itself this 
specification recommends to delegate this task to the IoT device operator and to take the 
necessary action to allow IoT devices to remain operational. 

## Open Issues

A list of open issues can be found at https://github.com/thomas-fossati/draft-tls13-iot/issues

# Security Considerations

This entire document is about security.

# IANA Considerations

IANA is asked to add the Option defined in {{early-data-option}} to the CoAP
Option Numbers registry.

~~~
+--------+------------+-----------+
| Number | Name       | Reference |
+--------+------------+-----------+
| TBD    | Early-Data | RFCThis   |
+--------+------------+-----------+
~~~
{: #early-data-option title="Early-Data Option"}

IANA is asked to add the Response Code defined in {{too-early-code}} to the
CoAP Response Code registry.

~~~
+--------+-------------+-----------+
| Code   | Description | Reference |
+--------+-------------+-----------+
| 4.25   | Too Early   | RFCThis   |
+--------+-------------+-----------+
~~~
{: #too-early-code title="Too Early Response Code"}

--- back
