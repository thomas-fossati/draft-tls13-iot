---
title: TLS/DTLS 1.3 Profiles for the Internet of Things
abbrev: TLS/DTLS 1.3 IoT Profiles
docname: draft-ietf-uta-tls13-iot-profile-latest
category: std
updates: 7925
consensus: true
submissiontype: IETF

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
    abbrev: H-BRS
    organization: University of Applied Sciences Bonn-Rhein-Sieg
    country: Germany
    email: Hannes.Tschofenig@gmx.net

 -
    ins: T. Fossati
    name: Thomas Fossati
    organization: "Linaro"
    email: Thomas.Fossati@linaro.org

 -
    ins: M. Richardson
    name: Michael Richardson
    organization: "Sandelman Software Works"
    email: mcr+ietf@sandelman.ca

contributor:
 -
    ins: J. Sosinowicz
    name: Juliusz Sosinowicz
 -
    ins: A. Kraus
    name: Achim Kraus

normative:
  RFC9147: DTLS13
  RFC8446: TLS13

informative:
  RFC9146:
  RFC7228:
  RFC4210:
  RFC7452:
  RFC6066:
  I-D.ietf-iotops-7228bis:
  I-D.ietf-pquip-pqc-engineers:
  PQC-ENERGY: DOI.10.1145/3587135.3592821
  PQC-PERF: DOI.10.1007/978-3-031-21280-2_24
  CoAP: RFC7252
  IEEE-802.1AR: DOI.10.1109/IEEESTD.2020.9052099
  FDO:
     author:
        org: FIDO Alliance
     title: FIDO Device Onboard Specification 1.1
     target: https://fidoalliance.org/specifications/download-iot-specifications/
     date: April 2022
  LwM2M-T:
     author:
        org: OMA SpecWorks
     title: "Lightweight Machine to Machine (LwM2M) V.1.2.2 Technical Specification: Transport Bindings"
     target: https://www.openmobilealliance.org/release/LightweightM2M/V1_2_2-20240613-A/
     date: June 2024
  LwM2M-C:
     author:
        org: OMA SpecWorks
     title: "Lightweight Machine to Machine (LwM2M) V.1.2.2 Technical Specification: Core"
     target: https://www.openmobilealliance.org/release/LightweightM2M/V1_2_2-20240613-A/
     date: June 2024

  Ambrose2017:
     author:
     - ins: C. Ambrose
       name: Christopher Ambrose
     - ins: J. W. Bos
       name: Joppe W. Bos
     - ins: B. Fay
       name: Björn Fay
     - ins: M. Joye
       name: Marc Joye
     - ins: M. Lochter
       name: Manfred Lochter
     - ins: B. Murray
       name: Bruce Murray
     date: 2017
     target: https://eprint.iacr.org/2017/975.pdf
     title: 'Differential Attacks on Deterministic Signatures'

--- abstract

RFC 7925 offers guidance to developers on using TLS/DTLS 1.2 for Internet of
Things (IoT) devices with resource constraints. This document is a
companion to RFC 7925, defining TLS/DTLS 1.3 profiles for IoT devices.
Additionally, it updates RFC 7925 with respect to the X.509 certificate
profile and ciphersuite requirements.

--- middle

# Introduction

In the rapidly evolving Internet of Things (IoT) ecosystem, communication security
is a critical requirement. The Transport Layer Security (TLS) and Datagram Transport
Layer Security (DTLS) protocols have been foundational for ensuring encryption,
integrity, and authenticity in communications. However, the constraints of a certain
class of IoT devices render conventional, off-the-shelf TLS/DTLS implementations
suboptimal for many IoT use cases. This document addresses these limitations by specifying TLS 1.3 and DTLS 1.3 profiles that are optimized for resource-constrained IoT devices.

Note that IoT devices vary widely in terms of capabilities. While some are highly
resource-constrained, others offer performance comparable to regular desktop computers
but operate without end-user interfaces. For a detailed description of the different
classes of IoT devices, please refer to {{RFC7228}} and {{I-D.ietf-iotops-7228bis}}.
It is crucial for developers to thoroughly assess the limitations of their IoT devices
and communication technologies to implement the most suitable optimizations.
The profiles in this document aim to balance strong security with the hardware and
software limitations of IoT devices.

TLS 1.3 has been re-designed and several previously defined extensions are not
applicable to the new version of TLS/DTLS anymore. The following features changed
with the transition from TLS 1.2 to 1.3:

- TLS 1.3 introduced the concept of post-handshake authentication messages, which
partially replaced the need for the re-negotiation feature {{?RFC5746}} available
in earlier TLS versions. However, the rekeying mechanism defined in {{Section 4.6.3 of -TLS13}}
does not provide post-compromise security (see {{Appendix E.1.5 of -TLS13}}).
Furthermore, post-handshake authentication defined in
{{Section 4.6.2 of -TLS13}} only offers client authentication (client-to-server).
The "Exported Authenticator" specification, see {{?RFC9261}}, added support
for mutual post-handshake authentication, but this requires the Certificate,
CertificateVerify and the Finished messages to be conveyed by the application
layer protocol, as it is exercised for HTTP/2 and HTTP/3 in {{?I-D.ietf-httpbis-secondary-server-certs}}.
Therefore, the application layer protocol must be enhanced whenever this feature is required.

- Rekeying of the application traffic secret does not lead to an update of the
exporter secret (see {{Section 7.5 of -TLS13}}) since the derived export secret is
based on the exporter_master_secret and not on the application traffic secret.

- Flight #4, which was used by EAP-TLS 1.2 {{?RFC5216}}, does not exist in TLS 1.3.
As a consequence, EAP-TLS 1.3 {{?RFC9190}} introduced a placeholder message.

- {{?RFC4279}} introduced PSK-based authentication to TLS, a feature re-designed
in TLS 1.3. The "PSK identity hint" defined in {{?RFC4279}}, which is used by the
server to help the client in selecting which PSK identity to use, is, however, not
available anymore in TLS 1.3.

- Finally, ciphersuites were deprecated and the RSA-based key transport is not
supported in TLS 1.3. As a consequence, only a Diffie-Hellman-based key exchange
is available for non-PSK-based (i.e., certificate-based) authentication. (For PSK-based authentication the
use of Diffie-Hellman is optional.)

The profiles in this specification are designed to be adaptable to the broad spectrum
of IoT applications, from low-power consumer devices to large-scale industrial
deployments. It provides guidelines for implementing TLS/DTLS 1.3 in diverse
networking contexts, including reliable, connection-oriented transport via TCP
for TLS, and lightweight, connectionless communication via UDP for DTLS. In
particular, DTLS is emphasized for scenarios where low-latency communication is
paramount, such as multi-hop mesh networks and low-power wide-area networks,
where the amount of data exchanged needs to be minimized.

This document offers comprehensive guidance for deploying secure
communication in resource-constrained IoT environments. It outlines best practices
for configuring TLS/DTLS 1.3 to meet the unique needs of IoT devices, ensuring
robust security without overwhelming their limited processing, memory, and power
resources. The document aims to facilitate the development of secure and efficient IoT
deployments and promote the broad adoption of secure communication standards.

This document updates {{RFC7925}} with respect to the X.509 certificate profile ({{certificate_profile}}) and ciphersuite requirements ({{ciphersuites}}).

# Conventions and Terminology

{::boilerplate bcp14}

This document reuses the terms "SHOULD+", "SHOULD-" and "MUST-" from {{!RFC8221}}.

# Credential Types

TLS/DTLS allow different credential types to be used. These include X.509
certificates and raw public keys, pre-shared keys (PSKs), and passwords.
The extensions used in TLS/DTLS differ depending on the credential types
supported.
Self-signed X.509 certificates are still X.509, not raw public keys; raw
public keys are conveyed via the raw_public_key extension.

This profile considers three authentication modes for IoT devices:
(1) certificate-based, (2) raw public key-based and (3) external PSK-based.
PSK with (EC)DHE is optional and not assumed by default.

TLS/DTLS 1.3 supports PSK-based authentication,
wherein PSKs can be established via session tickets from prior
connections or via some external, out-of-band mechanism. To distinguish
the two modes, the former is called resumption PSK and the latter
external PSK. For performance reasons the support for resumption PSKs
is often found in implementations that use X.509 certificates for
authentication.
Implementations that only support external PSKs are common in constrained
devices; implementations using certificates often also support resumption
PSKs for performance.

A "plain" PSK-based TLS/DTLS client or server, which only implements support
for external PSKs as its long-term credential, MUST implement the following extensions:

* Supported Versions,
* Cookie,
* Server Name Indication (SNI),
* Pre-Shared Key,
* PSK Key Exchange Modes, and
* Application-Layer Protocol Negotiation (ALPN).

Note that these extensions may also appear in ECDHE or resumption handshakes;
the requirement here is that external PSK-only endpoints MUST support them.

For external pre-shared keys, {{!RFC9258}} recommends that applications
SHOULD provision separate PSKs for (D)TLS 1.3 and prior versions.

Where possible, the importer interface defined in {{!RFC9258}} MUST be used
for external PSKs. This ensures
that external PSKs used in (D)TLS 1.3
are bound to a specific key derivation function (KDF) and hash function.

SNI is discussed in {{sni}}; the justification for implementing and using
the ALPN extension can be found in {{?RFC9325}}.

An implementation supporting authentication based on certificates and
raw public keys MUST support digital signatures with ecdsa_secp256r1_sha256. A
compliant implementation MUST support the key exchange with secp256r1 (NIST
P-256) and SHOULD support key exchange with X25519.

For TLS/DTLS clients and servers implementing raw public keys and/or
certificates the guidance for mandatory-to-implement extensions described in
{{Section 9.2 of -TLS13}} MUST be followed.

Entities deploying IoT devices may select credential types based on security
characteristics, operational requirements, cost, and other factors.
Consequently, this specification does not prescribe a single credential type
but provides guidance on considerations relevant to the use of particular types.

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

TLS 1.3 does not define compression of application data traffic, as offered by
previous versions of TLS. Applications are therefore responsible for transmitting
payloads that are either compressed or use a more efficient encoding otherwise.

With regards to the handshake itself, various strategies have
been applied to reduce the size of the exchanged payloads. TLS and DTLS 1.3 use less
overhead, depending on the type of key confirmations, when compared to previous versions of the
protocol.

# Forward Secrecy

RFC 8446 has removed Static RSA and Static Diffie-Hellman cipher suites, therefore all public-key-based key exchange mechanisms available in TLS 1.3 provide forward secrecy.

Pre-shared keys (PSKs) can be used with (EC)DHE key exchange to provide forward secrecy or can be used alone, at the cost of losing forward secrecy for the application data.
For PSK use, endpoints SHOULD use (EC)DHE to achieve forward secrecy; PSK-only
SHOULD be avoided unless the application can tolerate the loss of forward secrecy.

# Authentication and Integrity-only Cipher Suites

For a few, very specific Industrial IoT use cases {{?RFC9150}} defines two cipher
suites that provide data authenticity, but not data confidentiality. For details
and use constraints, defer to {{?RFC9150}} (especially {{Section 9 of RFC9150}}).
Implementations may not support these suites; deployments should not assume
availability. This document does not add new guidance beyond {{?RFC9150}}.

# Keep-Alive

The discussion in {{Section 10 of !RFC7925}} is applicable.

# Timers and ACKs

Compared to DTLS 1.2 timeout-based whole flight retransmission, DTLS 1.3 ACKs sensibly decrease the risk of congestion collapse which was the basis for the very conservative recommendations given in {{Section 11 of !RFC7925}}.

In general, the recommendations in {{Section 7.3 of -DTLS13}} regarding ACKs
apply to DTLS 1.3 only.
In particular, "(w)hen DTLS 1.3 is used in deployments with lossy networks, such as low-power, long-range radio networks as well as low-power mesh networks, the use of ACKs is recommended" to signal any sign of disruption or lack of progress.
This allows for selective or early retransmission, which leads to more efficient use of bandwidth and memory resources.

Due to the vast range of network technologies used in IoT deployments, from wired LAN to GSM-SMS, it's not possible to provide a universal recommendation for an initial timeout.
Therefore, it is RECOMMENDED that DTLS 1.3 implementations allow developers to explicitly set the initial timer value.
Developers SHOULD set the initial timeout to be twice the expected round-trip time (RTT),
but no less than 1000ms, which is a conservative default aligned with the guidance in
{{Section 11 of !RFC7925}}.
For specific application/network combinations, a sub-second initial timeout MAY be set.
In cases where no RTT estimates are available, a 1000ms initial timeout is suitable for the general Internet.

Regarding the timers used by the Return Routability Check (RRC) functionality, the recommendations in {{Section 5.5 of !I-D.ietf-tls-dtls-rrc}} apply.
Just like the handshake initial timers, it is RECOMMENDED that DTLS 1.2 and 1.3 implementations offer an option for their developers to explicitly set the RRC timer.

# Random Number Generation

The discussion in {{Section 12 of !RFC7925}} is applicable with one exception:
the ClientHello and the ServerHello messages in TLS 1.3 do not contain
gmt_unix_time component anymore.

# Server Name Indication {#sni}

This specification mandates the implementation of the Server Name Indication (SNI)
extension. Where privacy requirements require it, the ECH (Encrypted Client Hello)
extension {{?I-D.ietf-tls-esni}} prevents an on-path attacker to determine the domain
name the client is trying to connect to.

Since the Encrypted Client Hello extension requires use of Hybrid Public Key
Encryption (HPKE) {{?RFC9180}} and additional protocols require
further protocol exchanges and cryptographic operations, there is a certain
overhead associated with this privacy feature.

Note that in industrial IoT deployments the use of ECH may be disabled because
network administrators inspect the SNI to detect malicious behaviour.

Besides, to avoid leaking DNS lookups from network inspection altogether further
protocols are needed, including DNS-over-HTTPS (DoH) {{?RFC8484}},
DNS-over-TLS (DoT) {{?RFC7858}} and DNS-over-QUIC (DoQ) {{?RFC9250}}.

# Maximum Fragment Length Negotiation

The Maximum Fragment Length Negotiation (MFL) extension has been superseded by
the Record Size Limit (RSL) extension {{!RFC8449}}. Implementations in
compliance with this specification MUST implement the RSL extension and SHOULD
use it to indicate their RAM limitations.

# Crypto Agility

The recommendations in {{Section 19 of !RFC7925}} are applicable.

# Key Length Recommendations

The recommendations in {{Section 20 of !RFC7925}} are applicable.

# 0-RTT Data

{{Appendix E.5 of -TLS13}} establishes that:

> Application protocols MUST NOT use 0-RTT data without a profile that
> defines its use.  That profile needs to identify which messages or
> interactions are safe to use with 0-RTT and how to handle the
> situation when the server rejects 0-RTT and falls back to 1-RTT.

For any application protocol, 0-RTT MUST NOT be used unless a protocol-specific
profile exists. At the time of writing, no such profile has been defined for
CoAP {{CoAP}}. Therefore, 0-RTT MUST NOT be used by CoAP applications.

# Certificate Profile {#certificate_profile}

This section contains updates and clarifications to the certificate profile
defined in {{!RFC7925}}. The content of Table 1 of {{!RFC7925}} has been
split by certificate "type" in order to clarify exactly what requirements and
recommendations apply to which entity in the PKI hierarchy.

This profile does not define a specific certificate policy OID; deployments
MAY define one if needed for local policy enforcement.

A Device Identifier (DevID) consists of:

- a private key,
- a certificate containing the public key and the identifier certified by the
certificate issuer, and
- a certificate chain leading up to a trust anchor (typically the root certificate).

The IEEE 802.1AR specification {{IEEE-802.1AR}} introduces the concept of DevIDs and
defines two specialized versions:

- Initial Device Identifiers (IDevIDs): Provisioned during manufacturing to
provide a unique, stable identity for the lifetime of the device.
- Locally Significant Device Identifiers (LDevIDs): Provisioned after deployment
and typically used for operational purposes within a specific domain.

Thus, IDevIDs and LDevIDs are specialized forms of DevIDs as defined in IEEE 802.1AR.

The IDevID is typically provisioned by a manufacturer and signed by the
manufacturer CA. It is then used to obtain operational certificates,
the LDevIDs, from the operator or owner of the device. Some protocols
also introduce an additional hierarchy with application instance
certificates, which are obtained for use with specific applications.

IDevIDs are intended for device identity and initial onboarding or bootstrapping
protocols,
such as the Bootstrapping Remote Secure Key Infrastructure (BRSKI) protocol
{{?RFC8995}} or by LwM2M Bootstrap {{LwM2M-T}} {{LwM2M-C}}. Hence, the use of IDevIDs
is limited on purpose even though they have a long lifetime, or do not expire
at all. While some bootstrapping protocols use TLS (and therefore make use of
the IDevID as part of client authentication) there are other bootstrapping
protocols that do not use TLS/DTLS for client authentication, such as FIDO
Device Onboarding (FDO) {{FDO}}.  In many cases, the IDevID profile/content is
provided by those specifications. For these reasons, this
specification focuses on the description of LDevIDs.

This document uses the terminology and some of the rules for populating certificate
content defined in IEEE 802.1AR. However, this specification does not claim
conformance to IEEE 802.1AR; 802.1AR is broader and mandates hardware, security,
and process requirements outside IoT constraints, while this profile borrows
terminology and fields but intentionally omits those operational requirements.
Since such a compliance statement goes beyond the use of the terminology
and the certificate content and would include the use of management
protocols, fulfillment of certain hardware security requirements, and
interfaces to access these hardware security modules. Placing these
requirements on network equipment like routers may be appropriate but
designers of constrained IoT devices have opted for different protocols
and hardware security choices.

## All Certificates

To avoid repetition, this section outlines requirements on X.509
certificates applicable to all PKI entities. These requirements apply to
certificates issued within the IoT device PKI (root, subordinate, and end
entity certificates used to authenticate IoT devices), not to public WebPKI
server certificates. Note that TLS 1.3 allows conveying payloads other than
X.509 certificates in the Certificate message; this section focuses on X.509 v3
certificates and leaves other formats to other sections or specifications.

### Version

Certificates MUST be of type X.509 v3.

### Serial Number

CAs MUST generate non-sequential serial numbers greater than or equal to eight
(8) octets from a cryptographically secure pseudo-random number generator.
{{!RFC5280}} limits this field to a maximum of 20 octets.
The serial number MUST be unique
for each certificate issued by a given CA (i.e., the issuer name
and the serial number uniquely identify a certificate).

This requirement is aligned with {{!RFC5280}}.
CA/Browser Forum requirements for public WebPKI certificates are out of scope for this
profile.

### Signature

The signature MUST be ecdsa-with-SHA256 or stronger {{!RFC5758}}.

Note: In contrast to IEEE 802.1AR this specification does not require
end entity certificates, subordinate CA certificates, and CA
certificates to use the same signature algorithm. Furthermore,
this specification does not utilize RSA for use with constrained IoT
devices and networks.
For certificates expected to be validated by IoT devices, CAs SHOULD use a
single signature algorithm supported by those devices (e.g., ECDSA P-256).

### Issuer

The issuer field MUST contain a non-empty distinguished name (DN)
of the entity that has signed and issued the certificate in accordance
with {{!RFC5280}}.

### Validity

Vendors must determine the expected lifespan of their IoT devices. This
decision directly affects how long firmware and software updates are
provided for, as well as the level of maintenance that customers can expect.
It also affects the maximum validity period of certificates.
Constrained devices often lack precise UTC time; implementations SHOULD treat
time checks with coarse granularity (e.g., day- or hour-level) and ignore leap seconds
when validating notAfter.

In most IoT deployments, IDevIDs are provisioned with an unlimited lifetime as per {{IEEE-802.1AR}}.
For this purpose, a special value
for the notAfter date field, the GeneralizedTime value of 99991231235959Z,
is utilized.
This special value was introduced in {{Section 4.1.2.5 of !RFC5280}}.
When this is done, then the CA certificates and the certificates
of subordinate CAs have a maximum validity period.
Therefore,
careful consideration is required as to whether it is appropriate to issue
IDevID certificates with no maximum validity period.

LDevID certificates are, however, issued by the operator or owner,
and may be renewed at a regular interval using protocols, such
as Enrollment over Secure Transport (EST) {{?RFC7030}} or the
Certificate Management Protocol (CMP) {{?RFC9483}}.
It is therefore RECOMMENDED to limit the lifetime of these LDevID certificates
using the notBefore and notAfter fields, as described in {{Section 4.1.2.5 of
!RFC5280}}. Values MUST be expressed in Greenwich Mean Time (Zulu) and
MUST include seconds even where the number of seconds is zero.

Note that the validity period is defined as the period of time from notBefore
through notAfter, inclusive. This means that a hypothetical certificate with a
notBefore date of 9 June 2021 at 03:42:01 and a notAfter date of 7 September
2021 at 03:42:01 becomes valid at the beginning of the :01 second, and only
becomes invalid at the :02 second, a period that is 90 days plus 1 second.  So
for a 90-day, notAfter must actually be 03:42:00.

For devices without a reliable source of time we advise the use of a device
management solution, which typically includes a certificate management protocol,
to manage the lifetime of all the certificates used by the device. While this
approach does not utilize certificates to its widest extent, it is a solution
that extends the capabilities offered by a raw public key approach.

### Subject Public Key Info

The subjectPublicKeyInfo field indicates the algorithm and any associated
parameters for the ECC public key. This profile uses the id-ecPublicKey
algorithm identifier for ECDSA signature keys, as defined and specified in
{{!RFC5480}}. This specification assumes that devices support one of the
following algorithms:

- id-ecPublicKey with secp256r1,
- id-ecPublicKey with secp384r1, and
- id-ecPublicKey with secp521r1.

There is no requirement to use CA certificates and certificates of
subordinate CAs to use the same algorithm as the end entity certificate.
Certificates with longer lifetime may well use a cryptographically stronger
algorithm. However, CAs (or their administrators) that issue certificates
intended to be validated by constrained IoT devices SHOULD select algorithms
supported by those devices to ensure successful validation (e.g., P-256).

### Certificate Revocation Checks

The Certificate Revocation Lists (CRLs) distribution points extension has
been defined in RFC 5280 to identify how CRL information is obtained. The
Authority Information Access (AIA) extension indicates where to find additional
information about the CA, such as how to access information
like the online certificate status service (OCSP) or a CA issuer
certificate. Constrained IoT devices often do not perform OCSP or CRL
checks. Therefore, CRL distribution points and AIA
for OCSP SHOULD NOT be set in IoT device certificates; if set, they MUST NOT
be marked critical. AIA MAY be used solely for caIssuer to enable chain
fetching by peers that have sufficient resources.

Instead of using CRLs or OCSP this document follows the guidance in
{{Section 4.4.3 of !RFC7925}}: for certificate revocation, neither
OCSP nor CRL are used by constrained IoT devices.
This text refers to OCSP/CRL checks during the handshake; continuous
certificate validity checks are out of scope and left to application policy.

The use of device management protocols for IoT devices, which often include
an onboarding or bootstrapping mechanism, has also seen considerable uptake
in deployed devices. These protocols, some of which are standardized,
allow for the distribution and updating of certificates on demand. An example
of a standardized IoT device management protocol is the Lightweight Machine-to-Machine
(LwM2M) {{LwM2M-T}} {{LwM2M-C}} protocol. Device management protocols enable a
deployment model where IoT devices utilize end entity certificates with
shorter lifetime making certificate revocation protocols, like OCSP
and CRLs, less relevant. Certificate updates do not affect existing TLS
sessions; re-authentication or session re-establishment is an application
policy decision. This is particularly important when long-lived TLS
connections are used. In such a case, the post-handshake
authentication exchange is triggered when the application requires it. TLS 1.3 provides
client-to-server post-handshake authentication only. Mutual
authentication via post-handshake messages is available by the use of the "Exported
Authenticator" {{?RFC9261}} but requires the application layer protocol
to carry the payloads.
If continuous validation is required, the application must trigger
re-authentication or re-establish a new TLS session; TLS alone does not
mandate continuous checks.

Hence, instead of performing certificate revocation checks on the IoT device
itself this it is RECOMMENDED to delegate this task to the IoT device
operator and to take the necessary action to allow IoT devices to remain
operational.

## Root CA Certificate

This section outlines the requirements for root CA certificates.

### Subject

{{!RFC5280}} mandates that Root CA certificates MUST have a non-empty subject field. The subject field MUST contain the commonName, the organizationName, and the countryName attribute and MAY contain an organizationalUnitName attribute.
If a subjectAltName extension is present, it SHOULD be set to a value
consistent with the subject and SHOULD NOT be marked critical.

### Authority Key Identifier

{{Section 4.2.1.1 of !RFC5280}} defines the Authority Key Identifier as follows:
"The authority key identifier extension provides a means of identifying the
public key corresponding to the private key used to sign a certificate. This
extension is used where an issuer has multiple signing keys."

The Authority Key Identifier extension SHOULD be set to aid path construction.
If it is set, it MUST NOT be marked critical, and MUST contain the
subjectKeyIdentifier of this certificate.

### Subject Key Identifier

{{Section 4.2.1.2 of !RFC5280}} defines the SubjectKeyIdentifier as follows:
"The subject key identifier extension provides a means of identifying
certificates that contain a particular public key."

The Subject Key Identifier extension MUST be set, MUST NOT be marked critical,
and MUST contain the key identifier of the public key contained in the subject
public key info field. This profile aligns with CA/Browser Forum for CA certificates.

The subjectKeyIdentifier is used by path construction algorithms to identify which CA has signed a subordinate certificate.

### Key Usage

{{!RFC5280}} defines the key usage field as follows: "The key usage extension defines
the purpose (e.g., encipherment, signature, certificate signing) of the key contained
in the certificate."

The Key Usage extension SHOULD be set; if it is set, it MUST be marked
critical, and the keyCertSign or cRLSign purposes MUST be set. Additional key
usages MAY be set depending on the intended usage of the public key.

{{!RFC5280}} defines the extended key usage as follows: "This extension indicates
one or more purposes for which the certified public key may be used, in addition to
or in place of the basic purposes indicated in the key usage extension."

This extendedKeyUsage extension MUST NOT be set in CA certificates.


### Basic Constraints

{{!RFC5280}} states that "The Basic Constraints extension identifies whether the subject
of the certificate is a CA and the maximum depth of valid certification paths that include
this certificate. The cA boolean indicates whether the certified public key may be used to
verify certificate signatures."

For the pathLenConstraint RFC 5280 makes further statements:

- "The pathLenConstraint field is meaningful only if the cA boolean is asserted and the
key usage extension, if present, asserts the keyCertSign bit. In this case, it gives the
maximum number of non-self-issued intermediate certificates that may follow this
certificate in a valid certification path."
- "A pathLenConstraint of zero indicates that no non-self-issued intermediate CA
certificates may follow in a valid certification path."
- "Where pathLenConstraint does not appear, no limit is imposed."
- "Conforming CAs MUST include this extension in all CA certificates that contain public
keys used to validate digital signatures on certificates and MUST mark the extension as
critical in such certificates."

The Basic Constraints extension MUST be set, MUST be marked critical, the cA flag MUST
be set to true and the pathLenConstraint MUST be omitted.

## Subordinate CA Certificate

This section outlines the requirements for subordinate CA certificates.

### Subject

The subject field MUST be set and MUST contain the commonName, the organizationName,
and the countryName attribute and MAY contain an organizationalUnitName attribute.


### Authority Key Identifier

The Authority Key Identifier extension MUST be set, MUST NOT be marked critical, and
MUST contain the subjectKeyIdentifier of the CA that issued this certificate.

### Subject Key Identifier

The Subject Key Identifier extension MUST be set, MUST NOT be marked critical, and MUST
contain the key identifier of the public key contained in the subject public key info
field.

### Key Usage

The Key Usage extension MUST be set, MUST be marked critical, the keyCertSign or
cRLSign purposes MUST be set, and the digitalSignature purpose SHOULD be set.

Subordinate certification authorities SHOULD NOT have any extendedKeyUsage.
{{RFC5280}} reserves EKUs to be meaningful only in end entity certificates.

### Basic Constraints

The Basic Constraints extension MUST be set, MUST be marked critical, the cA flag
MUST be set to true and the pathLenConstraint SHOULD be omitted.

### CRL Distribution Point

The CRL Distribution Point extension SHOULD NOT be set. If it is set, it MUST NOT
be marked critical and MUST identify the CRL relevant for this certificate.

### Authority Information Access

The Authority Information Access (AIA) extension SHOULD NOT be set. If it is set, it MUST
NOT be marked critical and MUST identify the location of the certificate of the CA
that issued this certificate and the location it provides an online certificate
status service (OCSP).

## End Entity Certificate

This section outlines the requirements for end entity certificates.

### Subject

This section describes the use of end entity certificate primarily for (D)TLS
clients running on IoT devices. Operating (D)TLS servers on IoT devices is
possible but less common.

{{!RFC9525, Section 2}} mandates that the subject field not be used to identify a service.
However, certain IoT applications (for example, {{?I-D.ietf-anima-constrained-voucher}},
{{IEEE-802.1AR}}) use the subject field to encode the device serial number.

The requirement in {{Section 4.4.2 of !RFC7925}} to only use EUI-64 for end
entity certificates as a subject field is lifted.

Two fields are typically used to encode a device identifier, namely the
Subject and the subjectAltName fields. Protocol specifications tend to offer
recommendations about what identifiers to use and the deployment situation is
fragmented.

The subject field MAY include a unique device serial number. If a serial
number is included in the Subject DN, it MUST be encoded in the
X520SerialNumber attribute. If the serial number is used as an identifier,
it SHOULD also be placed in the subjectAltName (e.g., as a URI).
e.g., {{?RFC8995}} use requires a serial number in IDevID certificates.

{{!RFC5280}} defines: "The subject alternative name extension allows identities
to be bound to the subject of the certificate. These identities may be included
in addition to or in place of the identity in the subject field of the certificate."

The subject alternative name extension MAY be set. If it is set, it MUST NOT be
marked critical, except when the subject DN contains an empty sequence.

If the EUI-64 format is used to identify the subject of an end entity
certificate, it MUST be encoded as a Subject DN using the X520SerialNumber
attribute.  The contents of the field is a string of the form `HH-HH-HH-HH-HH-HH-HH-HH`
where 'H' is one of the symbols '0'-'9' or 'A'-'F'.

Per {{!RFC9525}} domain names MUST NOT be encoded in the subject commonName. Instead they
MUST be encoded in a subjectAltName of type DNS-ID. Domain names MUST NOT
contain wildcard (`*`) characters. The subjectAltName MUST NOT contain multiple
names.

Note: The IEEE 802.1AR recommends to encode information about a Trusted
Platform Module (TPM), if present, in the HardwareModuleName ({{Section 5 of ?RFC4108}}). This
specification does not follow this recommendation.

Where IoT devices are accepting (D)TLS connections, i.e., they are acting as a server,
it is unlikely that there will be a useful name that can go into the SNI. In general,
the use of SNI for the purpose of virtual hosting on constrained IoT devices is rare.
The IoT device cannot depend on a client providing a correct SNI, and so it MAY
ignore the extension when SNI is not used for virtual hosting.
This implies that IoT devices cannot do name-based virtual hosting of TLS connections.
In the unlikely event that an IoT device has multiple servers responding with different
server certificate, then the server SHOULD use different IP addresses or port numbers.


### Authority Key Identifier

The Authority Key Identifier extension MUST be set, MUST NOT be marked critical,
and MUST contain the subjectKeyIdentifier of the CA that issued this certificate.

### Subject Key Identifier

The Subject Key Identifier MUST NOT be included in end entity certificates, as it can be calculated from the public key, so it just takes up space.
End entity certificates are not used in path construction, so there is no ambiguity regarding which certificate chain to use, as there can be with subordinate CAs.

### Key Usage

The key usage extension MUST be set and MUST be marked as critical. For
signature verification keys the digitialSignature key usage purpose MUST
be specified. Other key usages are set according to the intended usage
of the key.

If enrollment of new certificates uses server-side key generation, encrypted
delivery of the private key is required. In such cases the key usage
keyEncipherment or keyAgreement MUST be set because the encrypted delivery
of the newly generated key involves encryption or agreement of a symmetric
key. On-device key generation is, however, the preferred approach.

As specified in {{IEEE-802.1AR}}, the extendedKeyUsage SHOULD NOT be present in
IDevID certificates, as it reduces the utility of the IDevID.
For locally assigned LDevID certificates to be usable with TLS,
the extendedKeyUsage MUST contain at least one of the following:
id-kp-serverAuth or id-kp-clientAuth.

# Update of Trust Anchors

Since the publication of RFC 7925 the need for firmware update mechanisms
has been reinforced and the work on standardizing a secure and
interoperable firmware update mechanism has made substantial progress,
see {{?RFC9019}}. RFC 7925 recommends to use a software / firmware update
mechanism to provision devices with new trust anchors. This approach only
addresses the distribution of trust anchors and not end entity certificates
or certificates of subordinate CAs.

As an alternative, certificate management protocols like CMP and EST
have also offered ways to update trust anchors. See, for example,
{{Section 2.1 of ?RFC7030}} for an approach to obtaining CA certificates
via EST.

# Certificate Overhead

In a public key-based key exchange, certificates and public keys are a major
contributor to the size of the overall handshake. For example, in a regular TLS
1.3 handshake with minimal ECC certificates and no subordinate CA utilizing
the secp256r1 curve with mutual authentication, around 40% of the entire
handshake payload is consumed by the two exchanged certificates.

Hence, it is not surprising that there is a strong desire to reduce the size of
certificates and certificate chains. This has led to various standardization
efforts. Below is a brief summary of what options an implementer has to reduce
the bandwidth requirements of a public key-based key exchange. Note that many
of the standardized extensions are not readily available in TLS/DTLS stacks since
optimizations typically get implemented last.

* Use elliptic curve cryptography (ECC) instead of RSA-based certificate due to
  the smaller certificate size. This document recommends the use of elliptic
  curve cryptography only.
* Avoid deep and complex CA hierarchies to reduce the number of subordinate CA
  certificates that need to be transmitted and processed. See
  {{?I-D.irtf-t2trg-taxonomy-manufacturer-anchors}} for a discussion about CA
  hierarchies.
  Most security requirements can be satisfied with a PKI depth of 3 (root CA, one subordinate CA, and end entity certificates).
* Pay attention to the amount of information conveyed inside certificates.
* Use session resumption to reduce the number of times a full handshake is
  needed.  Use Connection IDs {{RFC9146}}, when possible, to enable
  long-lasting connections.
* Use the TLS cached info {{?RFC7924}} extension to avoid sending certificates
  with every full handshake.
* Use client certificate URLs {{Section 5 of RFC6066}} instead of full certificates for
  clients. When applications perform TLS client authentication via
  DNS-Based Authentication of Named Entities (DANE) TLSA records then the
  {{?I-D.ietf-dance-tls-clientid}} specification may be used to reduce the
  packets on the wire. Note: The term "TLSA" does not stand for anything;
  it is just the name of the RRtype, as explained in {{?RFC6698}}.
* Use certificate compression as defined in
  {{?RFC8879}}.
* Use alternative certificate formats, where possible, such as raw public keys
  {{?RFC7250}} or CBOR-encoded certificates
  {{?I-D.ietf-cose-cbor-encoded-cert}}.

The use of certificate handles is a form of caching or compressing
certificates as well.

Although the TLS specification does not explicitly prohibit a server from
including trust anchors in the Certificate message - and some implementations
do - trust anchors SHOULD NOT be transmitted in this way. Trust anchors are
intended to be provisioned through out-of-band mechanisms, and any trust anchor
included in the TLS Certificate message cannot be assumed trustworthy by the client.
Including them therefore serves no functional purpose and unnecessarily consumes
bandwidth.

However, due to limited or asymmetric knowledge between client and server, omitting
trust anchors entirely is not always straightforward. Several scenarios highlight
this challenge:

- Pinned Server Certificates: In many device-to-cloud deployments (see {{Section 2.2 of RFC7452}}),
clients pin a specific server certificate. If the client has pinned the server
certificate, retransmitting it is unnecessary - but the server cannot reliably
determine this.

- Root Key Transitions: During root key rollover events (see {{Section 4.4 of RFC4210}}),
new trust anchors may not yet be fully distributed across all devices. This is especially
relevant in device-to-device communication {{Section 2.1 of RFC7452}}), where server roles
are determined dynamically and trust anchor distribution may be inconsistent.

- Non-Root Trust Anchors: In some deployments, the client's trust anchor may be an
intermediate CA rather than a root certificate. The server, lacking knowledge of the
client's trust store, cannot always select a certificate chain that aligns with the
client's trust anchor. To mitigate this, the client MAY include the Trusted CA Indication
extension (see {{Section 6 of RFC6066}}) in its ClientHello to signal the set of trust
anchors it supports.

{{RFC4210}} assumes the presence of a shared directory service for certificate retrieval.
In constrained or isolated IoT environments, this assumption does not hold. Trust anchors
are often distributed via firmware updates or fetched periodically using certificate
management protocols, such as EST (e.g., the /cacerts endpoint).

To support transitional trust states during trust anchor updates, devices MUST handle both:

- newWithOld: a certificate where the new trust anchor is signed by the old one, enabling
communication with peers that have not yet received the update.

- oldWithNew: a certificate where the old trust anchor is signed by the new one, enabling
verification of peers that still rely on the older anchor.

These certificates may be presented as an unordered set, and devices may not be able to
distinguish their roles without additional metadata.

A complication arises when the client's trust anchor is not a widely trusted root
CA. In that case, the server cannot determine in advance which trust anchors the
client has. To address this, the client MAY include the Trusted CA Indication
extension {{RFC6066}} in its ClientHello to signal the set of trust anchors it
supports, allowing the server to select an appropriate certificate chain.

Whether to utilize any of the above extensions or a combination of them depends
on the anticipated deployment environment, the availability of code, and the
constraints imposed by already deployed infrastructure (e.g., CA
infrastructure, tool support).

# Ciphersuites {#ciphersuites}

According to {{Section 4.5.3 of -DTLS13}}, the use of AES-CCM with 8-octet
authentication tags (CCM_8) is considered unsuitable for general use with DTLS.
This is because it has low integrity limits (i.e., high sensitivity to
forgeries) which makes endpoints that negotiate ciphersuites based on such AEAD
vulnerable to a trivial DoS attack. See also {{Sections 5.3 and 5.4 of
?I-D.irtf-cfrg-aead-limits}} for further discussion on this topic, as well as
references to the analysis supporting these conclusions.

Specifically, {{-DTLS13}} warns that:

~~~
> TLS_AES_128_CCM_8_SHA256 MUST NOT be used in DTLS without additional
> safeguards against forgery. Implementations MUST set usage limits for
> AEAD_AES_128_CCM_8 based on an understanding of any additional forgery
> protections that are used.
~~~

Since all the ciphersuites required by {{RFC7925}} and {{CoAP}} rely on CCM_8,
there is no alternate ciphersuite available for applications that aim to
eliminate the security and availability threats related to CCM_8 while retaining
interoperability with the larger ecosystem.

In order to ameliorate the situation, it is RECOMMENDED that
implementations support the following two ciphersuites for TLS 1.3:

* `TLS_AES_128_GCM_SHA256`
* `TLS_AES_128_CCM`

and offer them as their first choice.  These ciphersuites provide
confidentiality and integrity limits that are considered acceptable in the most
general settings.  For the details on the exact bounds of both ciphersuites see
{{Section 4.5.3 of -DTLS13}}.  Note that the GCM-based ciphersuite offers
superior interoperability with cloud services at the cost of a slight increase
in the wire and peak RAM footprints.

When the GCM-based ciphersuite is used with TLS 1.2, the recommendations in
{{Section 7.2.1 of !RFC9325}} related to deterministic nonce generation
apply.  In addition, the integrity limits on key usage detailed in {{Section 4.4
of !RFC9325}} also apply.

{{tab-cipher-reqs}} summarizes the recommendations regarding ciphersuites:

| Ciphersuite | MTI Requirement |
|--|--|
| `TLS_AES_128_CCM_8_SHA256` | MUST- |
| `TLS_AES_128_CCM` | SHOULD+ |
| `TLS_AES_128_GCM_SHA256` | SHOULD+ |
{: #tab-cipher-reqs align="left" title="TLS 1.3 Ciphersuite Requirements"}

# Fault Attacks on Deterministic Signature Schemes

A number of passive side-channel attacks as well as active fault-injection
attacks (e.g., {{Ambrose2017}}) have been demonstrated to be successful in allowing a malicious
third party to gain information about the signing key if a fully deterministic
signature scheme (e.g., ECDSA {{?RFC6979}} or EdDSA {{?RFC8032}}) is used.

Most of these attacks assume physical access to the device and are therefore
especially relevant to smart cards as well as IoT deployments with poor or
non-existent physical security.

In this security model, it is recommended to combine both randomness and
determinism, for example, as described in
{{?I-D.irtf-cfrg-det-sigs-with-noise}}.

# Post-Quantum Cryptography (PQC) Considerations

The recommendations and ciphersuites in this profile are based on classical
cryptography and are not quantum-resistant.

As detailed in {{I-D.ietf-pquip-pqc-engineers}}, the IETF is actively working to address the challenges of adopting PQC in various protocols, including TLS. The document highlights key aspects engineers must consider, such as algorithm selection, performance impacts, and deployment strategies. It emphasizes the importance of gradual integration of PQC to ensure secure communication while accounting for the increased computational, memory, and bandwidth requirements of PQC algorithms. These challenges are especially relevant in the context of IoT, where device constraints limit the adoption of larger key sizes and more complex cryptographic operations {{PQC-PERF}}. Besides, any choice need to careful evaluate the associated energy requirements {{PQC-ENERGY}}.

The work of incorporating PQC into TLS {{?I-D.ietf-uta-pqc-app}} {{?I-D.ietf-pquip-pqc-hsm-constrained}} is still ongoing, with key exchange message sizes increasing due to larger public keys. These larger keys demand more flash storage and higher RAM usage, presenting significant obstacles for resource-constrained IoT devices. The transition from classical cryptographic algorithms to PQC will be a significant challenge for constrained IoT devices, requiring careful planning to select hardware suitable for the task considering the lifetime of an IoT product.

# Privacy Considerations

The privacy considerations in {{Section 22 of !RFC7925}} largely continue to
apply. However, compared to TLS 1.2 and DTLS 1.2, TLS 1.3 and DTLS 1.3 encrypt
a larger portion of the handshake, which reduces the amount of identity and
credential metadata observable on the wire by passive attackers. Extensions,
such as the encrypted ClientHello, further increase privacy protection.

Certificate fields can expose stable device identifiers and other metadata.
In particular, IDevIDs and LDevIDs may reveal manufacturer identity, device
serial numbers, or other information to peers. Protection against passive
observers is, however, substantially improved since certificates are not
transmitted in the clear in TLS 1.3 and DTLS 1.3.

Where privacy is a deployment requirement, implementations and PKI profiles
should include only the minimum identity information needed for authorization
and interoperability.

When Connection IDs are used with DTLS 1.3, CID negotiation in post-handshake
messages is encrypted and integrity protected. In addition, record sequence
numbers are encrypted. Compared to DTLS 1.2 CID, this makes tracking by on-path
adversaries more difficult and improves privacy in multi-home and mobile
deployments ({{Section 11 of -DTLS13}}).

# Security Considerations

This entire document is about security.

# IANA Considerations

This document makes no requests to IANA.

--- back

# Acknowledgments
{:unnumbered}

We would like to thank
Henk Birkholz,
Hendrik Brockhaus,
Ben Kaduk,
John Mattsson,
Daniel Migault,
Tiru Reddy,
Rich Salz, and
Marco Tiloca.
