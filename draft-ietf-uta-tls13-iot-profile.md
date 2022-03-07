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

normative:
  DTLS13: I-D.ietf-tls-dtls13
  RFC7525bis: I-D.ietf-uta-rfc7525bis

informative:
  DTLS-CID: I-D.ietf-tls-dtls-connection-id
  CoAP: RFC7252

--- abstract

This document is a companion to RFC 7925 and defines TLS/DTLS 1.3 profiles for
Internet of Things devices.  It also updates RFC 7925 with regards to the X.509
certificate profile.

--- middle

# Introduction

This document defines a profile of DTLS 1.3 {{DTLS13}} and TLS
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

* Supported Versions,
* Cookie,
* Server Name Indication (SNI),
* Pre-Shared Key,
* PSK Key Exchange Modes, and
* Application-Layer Protocol Negotiation (ALPN).

The SNI extension is discussed in this document and the justification
for implementing and using the ALPN extension can be found in {{RFC7525bis}}.

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

TLS 1.3 does not have support for compression of application data traffic, as offered
by previous versions of TLS. Applications are therefore responsible for transmitting
payloads that are either compressed or use a more efficient encoding otherwise.

With regards to the handshake itself, various strategies have
been applied to reduce the size of the exchanged payloads. TLS and DTLS 1.3 use less
overhead, depending on the type of key confirmations, when compared to previous versions of the
protocol. Additionally, the work on Compact TLS (cTLS) {{?I-D.ietf-tls-ctls}} has taken compression of the handshake
a step further by utilizing out-of-band knowledge between the communication parties to reduce
the amount of data to be transmitted at each individual handshake, among applying other techniques.

# Perfect Forward Secrecy

TLS 1.3 allows the use of PFS with all ciphersuites since the support for it is
negotiated independently.

# Keep-Alive

The discussion in Section 10 of {{!RFC7925}} is applicable.

# Timeouts

The recommendation in Section 11 of {{!RFC7925}} is applicable. In particular
this document RECOMMENDED to use an initial timer value of 9 seconds with
exponential back off up to no less then 60 seconds.

# Random Number Generation

The discussion in Section 12 of {{!RFC7925}} is applicable with one exception:
the ClientHello and the ServerHello messages in TLS 1.3 do not contain
gmt_unix_time component anymore.

# Server Name Indication

This specification mandates the implementation of the Server Name Indication (SNI)
extension. Where privacy requirements require it, the Encrypted Client Hello
extension {{?I-D.ietf-tls-esni}} prevents an on-path attacker to determine the domain
name the client is trying to connect to.

Note: To avoid leaking DNS lookups from network inspection altogether further
protocols are needed, including DoH {{?RFC8484}} and DPRIVE {{?RFC7858}} {{?RFC8094}}.
Since the Encrypted Client Hello extension requires use of Hybrid Public Key
Encryption (HPKE) {{?I-D.irtf-cfrg-hpke}} and additional protocols require
further protocol exchanges and cryptographic operations, there is a certain
amount of overhead associated with this privacy property.

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

This document specifies the Early-Data option, which indicates that the
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

<cref>Note that 4.25 is just the suggested CoAP response code, which has not been
registered yet.</cref>

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

No maximum validity period is mandated.  Validity values are expressed in
notBefore and notAfter fields, as described in Section 4.1.2.5 of {{!RFC5280}}.
In particular, values MUST be expressed in Greenwich Mean Time (Zulu) and MUST
include seconds even where the number of seconds is zero.

Note that the validity period is defined as the period of time from notBefore
through notAfter, inclusive.  This means that a hypothetical certificate with a
notBefore date of 9 June 2021 at 03:42:01 and a notAfter date of 7 September
2021 at 03:42:01 becomes valid at the beginning of the :01 second, and only
becomes invalid at the :02 second, a period that is 90 days plus 1 second.  So
for a 90-day, notAfter must actually be 03:42:00.

In many cases it is necessary to indicate that a certificate does not expire.
This is likely to be the case for manufacturer-provisioned certificates.
RFC 5280 provides a simple solution to convey the fact that a certificate
has no well-defined expiration date by setting the notAfter to the
GeneralizedTime value of 99991231235959Z.

Some devices might not have a reliable source of time and for those devices it
is also advisable to use certificates with no expiration date and to let a
device management solution manage the lifetime of all the certificates used by
the device. While this approach does not utilize certificates to its widest extent,
it is a solution that extends the capabilities offered by a raw public key approach.

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

# Certificate Overhead

In a public key-based key exchange, certificates and public keys are a major
contributor to the size of the overall handshake. For example, in a regular TLS
1.3 handshake with minimal ECC certificates and no intermediate CA utilizing
the secp256r1 curve with mutual authentication, around 40% of the entire
handshake payload is consumed by the two exchanged certificates.

Hence, it is not surprising that there is a strong desire to reduce the size of
certificates and certificate chains. This has lead to various standardization
efforts. Here is a brief summary of what options an implementer has to reduce
the bandwidth requirements of a public key-based key exchange:

* Use elliptic curve cryptography (ECC) instead of RSA-based certificate due to
  the smaller certificate size.
* Avoid deep and complex CA hierarchies to reduce the number of intermediate CA
  certificates that need to be transmitted.
* Pay attention to the amount of information conveyed inside certificates.
* Use session resumption to reduce the number of times a full handshake is
  needed.  Use Connection IDs {{DTLS-CID}}, when possible, to enable
  long-lasting connections.
* Use the TLS cached info {{?RFC7924}} extension to avoid sending certificates
  with every full handshake.
* Use client certificate URLs {{?RFC6066}} instead of full certificates for
  clients.
* Use certificate compression as defined in
  {{?I-D.ietf-tls-certificate-compression}}.
* Use alternative certificate formats, where possible, such as raw public keys
  {{?RFC7250}} or CBOR-encoded certificates
  {{?I-D.ietf-cose-cbor-encoded-cert}}.

The use of certificate handles, as introduced in cTLS {{?I-D.ietf-tls-ctls}},
is a form of caching or compressing certificates as well.

Whether to utilize any of the above extensions or a combination of them depends
on the anticipated deployment environment, the availability of code, and the
constraints imposed by already deployed infrastructure (e.g., CA
infrastructure, tool support).

# Ciphersuites

Section 4.5.3 of {{DTLS13}} flags AES-CCM with 8-octet authentication tags
(CCM_8) as unsuitable for general use with DTLS.  In fact, due to its low
integrity limits (i.e., a high sensitivity to forgeries), endpoints that
negotiate ciphersuites based on such AEAD are susceptible to a trivial DoS.
(See also Section 5.3 and 5.4 of {{?I-D.irtf-cfrg-aead-limits}} for further
discussion on this topic, as well as references to the analysis supporting
these conclusions.)

Specifically, {{DTLS13}} warns that:

> "TLS_AES_128_CCM_8_SHA256 MUST NOT be used in DTLS without additional
> safeguards against forgery. Implementations MUST set usage limits for
> AEAD_AES_128_CCM_8 based on an understanding of any additional forgery
> protections that are used."

Since all the ciphersuites mandated by {{RFC7925}} and {{CoAP}} are based on
CCM_8, there is no stand-by ciphersuite to use for applications that want to
avoid the security and availability risks associated with CCM_8 while retaining
interoperability with the rest of the ecosystem.

In order to ameliorate the situation, this document RECOMMENDS that
implementations support the following two ciphersuites:

* TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
* TLS_ECDHE_ECDSA_WITH_AES_128_CCM

and offer them as their first choice.  These ciphersuites provide
confidentiality and integrity limits that are considered acceptable in the most
general settings.  For the details on the exact bounds of both ciphersuites see
Section 4.5.3 of {{DTLS13}}.  Note that the GCM-based ciphersuite offers
superior interoperability with cloud services at the cost of a slight increase
in the wire and peak RAM footprints.

When the GCM-based ciphersuite is used with TLS 1.2, the recommendations in
Section 6.2.1 of {{RFC7525bis}} related to deterministic nonce generation
apply.  In addition, the integrity limits on key usage detailed in Section 4.4
of {{RFC7525bis}} also apply.

# Open Issues

A list of open issues can be found at https://github.com/thomas-fossati/draft-tls13-iot/issues

# Security Considerations

This entire document is about security.

# Acknowledgements

We would like to thank Ben Kaduk and John Mattsson.

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
