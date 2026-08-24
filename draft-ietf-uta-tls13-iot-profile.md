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
    organization: University of the Bundeswehr Munich
    abbrev: UniBw M.
    city: Neubiberg
    region: Bavaria
    country: Germany
    code: 85577
    email: hannes.tschofenig@gmx.net

 -
    ins: T. Fossati
    name: Thomas Fossati
    organization: "NVIDIA"
    email: tfossati@nvidia.com

 -
    ins: M. Richardson
    name: Michael Richardson
    organization: "Sandelman Software Works"
    email: mcr+ietf@sandelman.ca

 -
    ins: D. Migault
    name: Daniel Migault
    organization: Ericsson
    country: Canada
    email: daniel.migault@ericsson.com

contributor:
 -
    ins: J. Sosinowicz
    name: Juliusz Sosinowicz
 -
    ins: A. Kraus
    name: Achim Kraus

normative:
  RFC9147: DTLS13
  RFC9846: TLS13
  RFC6520:
  I-D.ietf-lamps-macaddress-on:
  I-D.ietf-iotops-7228bis:
  RFC6066:
  RFC7301:
  RFC7250:

informative:
  RFC9146:
  RFC7228:
  RFC9810: cmp
  RFC8937:
  RFC9483: lw-cmp
  I-D.ietf-iotops-iot-dns-guidelines:
  RFC9958:
  RFC9973:
  I-D.ietf-tls-pake:
  I-D.ietf-tls-extended-key-update:
  PQC-ENERGY: DOI.10.1145/3587135.3592821
  PQC-PERF: DOI.10.1007/978-3-031-21280-2_24
  NIST-SP-800-131Ar3:
     author:
      - ins: E. Barker
        name: Elaine Barker
      - ins: A. Roginsky
        name: Allen Roginsky
     title: "Transitioning the Use of Cryptographic Algorithms and Key Lengths"
     target: https://doi.org/10.6028/NIST.SP.800-131Ar3.ipd
     date: October 2024
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
  Toms-Hardware-Oculus-Rift-2018:
   author:
    - ins: S. Colaner
      name: Seth Colaner
   title: "How To Patch Your Oculus Rift"
   target: https://www.tomshardware.com/news/oculus-rift-runtime-error-fix%2C36629.html
   date: March 2018
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
suboptimal for many IoT use cases. This document addresses these limitations by specifying
TLS 1.3 and DTLS 1.3 profiles that are optimized for resource-constrained IoT devices.

Note that IoT devices vary widely in terms of capabilities. While some are highly
resource-constrained, others offer performance comparable to regular desktop computers
but operate without end-user interfaces. For a detailed description of the different
classes of IoT devices, please refer to {{RFC7228}} and {{I-D.ietf-iotops-7228bis}}.
It is crucial for developers to thoroughly assess the limitations of their IoT devices
and communication technologies to implement the most suitable optimizations.
The profiles in this document aim to balance strong security with the hardware and
software limitations of IoT devices.

TLS 1.3 has been re-designed and several previously defined extensions are no longer
applicable to the new version of TLS/DTLS. The following features changed
with the transition from TLS 1.2 to 1.3:

- TLS 1.3 introduced the concept of post-handshake authentication messages, which
partially replaced the need for the re-negotiation feature {{?RFC5746}} available
in earlier TLS versions. However, the rekeying mechanism defined in {{Section 4.7.3 of -TLS13}}
does not provide post-compromise security (see {{Appendix F.1.5 of -TLS13}}).
Furthermore, post-handshake authentication defined in
{{Section 4.7.2 of -TLS13}} only offers client authentication (client-to-server).
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

- {{?RFC4279}} introduced PSK-based authentication to TLS, including the
"PSK identity hint", which allowed a server to help the client select a PSK
identity. TLS 1.3 removed this separate server-provided hint. Instead, the
client offers one or more PSK identities in the `pre_shared_key` extension, and
the server selects one of them as part of the handshake. As a result, TLS 1.3
clients need sufficient local or application-provided context, such as the
intended server name, the application protocol, or
local configuration, to determine which PSK identities to offer.

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

This document updates {{RFC7925}} with respect to the X.509 certificate profile
({{certificate_profile}}) and ciphersuite requirements ({{ciphersuites}}).
The update is intentionally limited. {{RFC7925}} remains the TLS/DTLS 1.2
profile for constrained IoT devices and is still relevant for legacy
deployments. This is particularly important in industrial IoT deployments,
where devices, certification programs, and operational processes often have
long lifecycles and therefore transition to newer protocol versions more
slowly than general-purpose Internet software. This document does not replace
the TLS/DTLS 1.2 protocol guidance in {{RFC7925}}. Instead, it defines the
corresponding TLS/DTLS 1.3 profile and updates only those {{RFC7925}}
requirements that need to change for TLS/DTLS 1.3 deployments, namely the
certificate profile and ciphersuite recommendations.

This document is organized as follows.
The sections from {{credential_types}}
through {{zerortt}} profile TLS/DTLS credentials and protocol features relevant
to constrained IoT deployments, including credential types, session resumption,
forward secrecy, server name indication (SNI), record sizing, crypto agility,
key lengths, and 0-RTT data. {{certificate_profile}} updates
and clarifies the X.509 certificate profile from {{RFC7925}}.

TLS protocol compatibility is a required basis, but it is insufficient to permit interoperability at the level of authentication and authorization.
{{trust_anchor_update}} and {{certificate_overhead}} discuss trust-anchor update
and certificate-size overhead. {{ciphersuites}} updates the ciphersuite
requirements.

The remaining sections discuss fault attacks, post-quantum
cryptography, privacy, and security considerations.

# Conventions and Terminology

{::boilerplate bcp14}

This document uses TLS terminology from {{-TLS13}}, DTLS terminology from
{{-DTLS13}}, and X.509 certificate and certification path terminology from
{{!RFC5280}}. IoT device-class terminology follows {{RFC7228}} and
{{I-D.ietf-iotops-7228bis}}. The DevID, IDevID, and LDevID terms used in the
certificate profile are introduced in {{IEEE-802.1AR}} and described in
{{certificate_profile}}.

# Credential Types
{: #credential_types}

TLS/DTLS allow different credential types to be used. These include X.509
certificates and raw public keys, pre-shared keys (PSKs), and passwords.
The extensions used in TLS/DTLS differ depending on the credential types
supported.
Self-signed X.509 certificates are still X.509, not raw public keys; raw
public keys are conveyed via the raw_public_key extension {{RFC7250}}.
When raw public keys are
used for peer authentication, deployments need to bind the authenticated key to
the expected peer identity. {{Appendix F.9 of -TLS13}} describes misbinding
attacks in such deployments and identifies mitigations, including the validation of the `server_name`
extension where a domain name is used.

Password-authenticated key exchange (PAKE) mechanisms allow two endpoints to
authenticate and establish keys from a low-entropy shared secret, such as a
user-entered password, without using that secret directly as a TLS PSK. Such
mechanisms have been defined for earlier versions of TLS, and new work is
underway to add PAKE authentication to TLS 1.3 {{I-D.ietf-tls-pake}}. The
deployment model for PAKE mechanisms in constrained IoT environments is
still evolving. This profile therefore does not cover password-authenticated
TLS deployments.

This profile considers three authentication modes for IoT devices:
(1) certificate-based, (2) raw public key-based and (3) external PSK-based.
TLS/DTLS 1.3 supports both PSK-only and PSK with (EC)DHE key exchange modes.
For PSK use, endpoints MUST use (EC)DHE where possible to provide forward
secrecy. PSK-only is acceptable when the loss of forward secrecy is
explicitly accepted for the IoT deployment; see {{forward_secrecy}}.

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

Endpoints that use external PSKs as their only long-term credential still
follow the TLS/DTLS 1.3 extension requirements according to their
applicability; see {{table-mandatory-extensions}}. This profile differs from
certificate-based and raw-public-key-based deployments only in that endpoints
that exclusively support external PSK authentication do not need to implement
certificate-authentication extensions or signature algorithm support. When
such endpoints offer or negotiate `psk_dhe_ke`, the `supported_groups` and
`key_share` extensions are required as specified by TLS 1.3. When `psk_ke` is
used without (EC)DHE, those extensions are not needed for that handshake.

For external pre-shared keys, {{!RFC9258}} recommends that applications
SHOULD provision separate PSKs for (D)TLS 1.3 and prior versions.
Additional guidance for using external PSKs in TLS, including PSK entropy
requirements and security properties, is provided by {{?RFC9257}}.

Where possible, the importer interface defined in {{!RFC9258}} MUST be used
for external PSKs. This ensures that external PSKs used in (D)TLS 1.3
are bound to a specific key derivation function (KDF) and hash function.

An implementation supporting authentication based on certificates and
raw public keys MUST support digital signatures with ecdsa_secp256r1_sha256. A
compliant implementation MUST support the key exchange with secp256r1 (NIST
P-256) and SHOULD support key exchange with X25519.

Entities deploying IoT devices may select credential types based on security
characteristics, operational requirements, cost, and other factors.
Consequently, this specification does not mandate a single credential type
but provides guidance on considerations relevant to the use of particular types.

TLS/DTLS 1.3 implementations conforming to this profile MUST follow the
mandatory-to-implement extension requirements in {{Section 9.2 of -TLS13}}.
For constrained IoT implementations, it is useful to have a single checklist
that maps TLS/DTLS 1.3 extension support to the credential modes and deployment
features used by this profile. {{table-mandatory-extensions}} provides that
implementation checklist. It summarizes the TLS/DTLS 1.3 requirements and the
additional extension requirements established by this profile; it does not
replace the normative requirements in the referenced sections.

| Extension | Applicability | Reference |
|---|---|---|
| `supported_versions` | TLS/DTLS 1.3 negotiation | {{Section 9.2 of -TLS13}} |
| `cookie` | HelloRetryRequest and DTLS use | {{Section 9.2 of -TLS13}} |
| `signature_algorithms` | Certificate authentication and other signature-based authentication mechanisms | {{Section 9.2 of -TLS13}} |
| `signature_algorithms_cert` | Certificate authentication where certificate signature algorithms are negotiated separately | {{Section 9.2 of -TLS13}} |
| `supported_groups` | DHE/ECDHE key exchange, including `psk_dhe_ke` | {{Section 9.2 of -TLS13}} |
| `key_share` | DHE/ECDHE key exchange, including `psk_dhe_ke` | {{Section 9.2 of -TLS13}} |
| `server_name` | Applications capable of using SNI | {{sni}} |
| `pre_shared_key` | PSK authentication and resumption | {{Section 9.2 of -TLS13}} |
| `psk_key_exchange_modes` | PSK authentication and resumption | {{Section 9.2 of -TLS13}} |
| `application_layer_protocol_negotiation` | Application protocol selection | {{alpn}} |
| `record_size_limit` | Constrained endpoints | {{record_size_limit}} |
{: #table-mandatory-extensions align="left" title="Mandatory and Profile-Specific Extension Requirements"}

# Error Handling

TLS 1.3 simplified the Alert protocol, but IoT deployments still need explicit
error-handling behavior above the TLS library. This is particularly important
in Industrial IoT applications where safety, availability, and deterministic
behavior are high priorities. Unattended devices often cannot rely on prompting
a user or on generic TLS-library defaults. Applications therefore need code and
policy for handling relevant TLS errors, including deciding which errors are
recoverable, when to retry or re-establish a connection, when to use an
alternative endpoint or credential, and when to enter a safe operational state.
The general guidance in {{Section 6 of !RFC7925}} continues to apply. However,
implementations using TLS 1.3 MUST follow the alert definitions and processing
rules in {{Section 6 of -TLS13}}. TLS 1.2-specific alerts for features that no
longer exist in TLS 1.3, such as `decompression_failure` and
`no_renegotiation`, are not used in TLS 1.3. TLS 1.3 also defines alerts such
as `missing_extension` for protocol violations involving required extensions.

# Session Resumption

TLS 1.3 has built-in support for session resumption by utilizing PSK-based
credentials established in an earlier exchange.
Session resumption can substantially reduce bandwidth, latency, and
cryptographic computation in IoT deployments because subsequent handshakes do
not need to repeat the full certificate-based authentication exchange. Servers
can issue resumption PSKs in a way that matches the expected reconnection
pattern of the deployment. The number of tickets issued, their lifetime, and
their reuse policy are deployment decisions that balance availability and
bandwidth savings against server state, anti-replay requirements, and privacy
considerations.

# Forward Secrecy {#forward_secrecy}

RFC 9846 has removed Static RSA and Static Diffie-Hellman cipher suites, therefore all public-key-based key exchange mechanisms available in TLS 1.3 provide forward secrecy.

Pre-shared keys (PSKs) can be used with (EC)DHE key exchange to provide forward secrecy or can be used alone, at the cost of losing forward secrecy for the application data.
For PSK use, endpoints SHOULD use (EC)DHE to achieve forward secrecy. PSK-only
is acceptable only when the loss of forward secrecy is explicitly accepted for
the IoT deployment.

TLS 1.3 KeyUpdate refreshes application traffic keys, but it does not inject
fresh key exchange input and therefore does not provide post-compromise
security for a long-lived session. Industrial IoT deployments can have
long-lived TLS or DTLS associations where reconnecting is operationally
undesirable. The Extended Key Update mechanism
{{I-D.ietf-tls-extended-key-update}} is being developed for such cases; it
performs a fresh key exchange inside an active TLS/DTLS 1.3 session and can
provide post-compromise security when the deployment requires it and both peers
support the extension.


# Keep-Alive

The discussion in {{Section 10 of !RFC7925}} is applicable.
When a TLS/DTLS-level keep-alive or path MTU discovery mechanism is needed,
use of the Heartbeat Extension defined in {{RFC6520}} is RECOMMENDED.

# Timers and ACKs

Compared to DTLS 1.2 timeout-based whole flight retransmission, DTLS 1.3 ACKs sensibly decrease the risk of congestion collapse which was the basis for the very conservative recommendations given in {{Section 11 of !RFC7925}}.

The recommendations in {{Section 7.3 of -DTLS13}} regarding ACKs apply.
In particular,

{: quote}
> When DTLS 1.3 is used in deployments with lossy networks, such as low-power, long-range radio networks as well as low-power mesh networks, the use of ACKs is recommended.

ACKs provide explicit feedback on which handshake messages have been received.
This enables endpoints to detect a lack of progress more quickly and to trigger selective or early retransmission, leading to more efficient use of bandwidth and memory.

Due to the vast range of network technologies used in IoT deployments, from wired LAN to GSM-SMS, it's not possible to provide a universal recommendation for an initial timeout.
Therefore, it is RECOMMENDED that DTLS 1.3 implementations allow developers to explicitly set the initial timer value.
Developers SHOULD set the initial timeout to be twice the expected round-trip time (RTT),
but no less than 1000ms, which is a conservative default aligned with the guidance in
{{Section 11 of !RFC7925}}.
For specific application/network combinations, a sub-second initial timeout MAY be set.
In cases where no RTT estimates are available, a 1000ms initial timeout is suitable for the general Internet.

Regarding the timers used by the Return Routability Check (RRC) functionality, the recommendations in {{Section 5.5 of !RFC9853}} apply.
Just like the handshake initial timers, it is RECOMMENDED that DTLS 1.2 and 1.3 implementations offer an option for their developers to explicitly set the RRC timer.

# Random Number Generation

The discussion in {{Section 12 of !RFC7925}} is applicable with one exception:
the ClientHello and the ServerHello messages in TLS 1.3 do not contain
gmt_unix_time component anymore.
For entropy generation and randomness considerations, implementers should also
consult {{RFC8937}}.

# Server Name Indication {#sni}

TLS 1.3 requires implementations to support the Server Name Indication (SNI)
extension when used with applications capable of using it
({{Section 9.2 of -TLS13}}).

IoT clients SHOULD send SNI when connecting to a named service, in particular
when the peer is a cloud service, a multi-tenant endpoint, or any server that
uses SNI for certificate or application-context selection. IoT clients MAY omit
SNI when the peer identity is established by other application-specific
configuration, such as a configured IP address and port, a pinned certificate,
a raw public key, or an external PSK identity. When no domain name is used, SNI
is not applicable.
When SNI is omitted in deployments using raw public keys or self-signed
certificates, the application needs another binding between the authenticated
key and the expected peer identity. Otherwise, the deployment can be vulnerable
to the misbinding attacks described in {{Appendix F.9 of -TLS13}}.

Deployments that require confidentiality of SNI and other ClientHello metadata
can use Encrypted ClientHello (ECH) {{?RFC9849}}. ECH is most applicable to
IoT deployments that use named cloud services or shared service infrastructure
and have explicit privacy requirements. Since ECH does not protect DNS lookups
or other metadata outside the TLS handshake, deployments that rely on ECH for
privacy also need to protect DNS resolution, for example using encrypted DNS
mechanisms; see {{I-D.ietf-iotops-iot-dns-guidelines}} for IoT-specific DNS
guidance. The applicability, deployment requirements, and limitations of ECH
are described in {{?RFC9849}}.

IoT servers MAY use SNI for certificate or application-context selection.
Authorization decisions are outside the scope of SNI and are based on the
authenticated peer credentials and local policy. If constrained clients are not
expected to send useful SNI values, deployments SHOULD prefer separate IP
addresses or port numbers when different server identities or certificates need
to be distinguished.

# Application-Layer Protocol Negotiation {#alpn}

The Application-Layer Protocol Negotiation (ALPN) extension {{RFC7301}} is
independent of the credential type used for TLS authentication.

Implementations conforming to this profile MUST support ALPN. Endpoints SHOULD
use ALPN when more than one application protocol, application protocol version, or
application context can be served by the same TLS endpoint, certificate, raw
public key, or PSK identity. When a deployment is restricted by configuration
to a single application protocol, ALPN MAY be omitted.

Use of ALPN helps prevent cross-protocol confusion attacks and follows the
guidance in {{Section 3.8 of ?RFC9325}}.

# Maximum Fragment Length Negotiation {#record_size_limit}

The Maximum Fragment Length Negotiation (MFL) extension has been superseded by
the Record Size Limit (RSL) extension {{!RFC8449}}. Implementations in
compliance with this specification MUST implement the RSL extension and MUST
use it to indicate their RAM or record-size limitations unless the default
record sizes, which require approximately 18 KB of memory for TLS 1.3
ciphertext and associated processing buffers, are acceptable for the IoT
deployment.

# Crypto Agility

The recommendations in {{Section 19 of !RFC7925}} are applicable.
The third bullet point in that section anticipated the evolution of cryptographic
hardware support in IoT devices. Today, chip manufacturers commonly provide
hardware acceleration for AES-CCM, as well as for other AES modes, including
AES-GCM. Note that the ciphersuite recommendations in this document now
include GCM, in addition to CCM, as described in {{ciphersuites}}.

# Key Length Recommendations

The recommendations in {{Section 20 of !RFC7925}} apply with the following
update. The recommendation for 112 bits of security strength, described there
as equivalent to a 112-bit symmetric key and a 233-bit ECC key, is raised to at
least 128 bits of security strength. Using the comparison in RFC 7925, this
corresponds to a 128-bit symmetric key and a 283-bit ECC key. For the
prime-field curves used by this profile, secp256r1 provides the intended
128-bit security strength. This update is consistent with the transition to
128-bit security strength discussed in {{NIST-SP-800-131Ar3}}.

# 0-RTT Data
{: #zerortt}

{{Appendix F.5 of -TLS13}} establishes that:

{: quote}
> Application protocols MUST NOT use 0-RTT data without a profile that
> defines its use.  That profile needs to identify which messages or
> interactions are safe to use with 0-RTT and how to handle the
> situation when the server rejects 0-RTT and falls back to 1-RTT.

For any application protocol, 0-RTT MUST NOT be used unless a protocol-specific
profile exists.

At the time of writing, no such profile has been defined for commonly used IoT
application protocols such as CoAP {{CoAP}} or MQTT (Message Queuing Telemetry
Transport). Therefore, this profile does not enable 0-RTT for CoAP, MQTT, or
other IoT application protocols that lack a protocol-specific 0-RTT profile.

# Certificate Profile {#certificate_profile}

This section contains updates and clarifications to the certificate profile
defined in {{!RFC7925}}. The content of Table 1 of {{!RFC7925}} has been
split by certificate "type" in order to clarify exactly what requirements and
recommendations apply to the certificates that make up a certification path
from a trust anchor to an end entity certificate.

This profile does not define a specific certificate policy OID; deployments
MAY define one if needed for local policy enforcement.

The terminology used in this section is not intended to restrict the scope of this profile to IEEE 802.1AR deployments.
Terms from {{IEEE-802.1AR}} are used because it conveniently distinguishes between manufacturer-provisioned and operational credentials, which is important in many IoT deployments.

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

The IDevID is typically provisioned by a manufacturer and signed by the
manufacturer CA. It is then used to obtain operational certificates,
the LDevIDs, from the operator or owner of the device. Some protocols
also introduce an additional hierarchy with application instance
certificates, which are obtained for use with specific applications.

IDevIDs are intended for device identity and initial onboarding or bootstrapping
protocols, such as the Bootstrapping Remote Secure Key Infrastructure (BRSKI)
protocol {{?RFC8995}} or LwM2M Bootstrap {{LwM2M-T}} {{LwM2M-C}}. The use of
IDevIDs is intentionally limited to such onboarding scenarios even though they
often have a long lifetime, or do not expire at all.

There are, however, multiple onboarding and bootstrapping approaches in use.
Some of them use TLS and therefore use the IDevID for client authentication,
while others, such as FIDO Device Onboarding (FDO) {{FDO}}, do not use TLS/DTLS
for client authentication. In many cases, the IDevID profile and content are
defined by those specifications. For these reasons, this specification focuses
on the description of operational certificates such as LDevIDs.

This document uses the terminology and some of the rules for populating certificate
content defined in IEEE 802.1AR. However, this specification does not claim
conformance to IEEE 802.1AR, which is broader and mandates hardware, security,
and process requirements outside the constraints of many IoT deployments. This
profile borrows terminology and selected certificate fields from IEEE 802.1AR
but intentionally omits those broader requirements.

## All Certificates

This section outlines the requirements for X.509 certificates that apply to all PKI entities.
These requirements apply to certificates issued within the IoT device PKI (i.e., root, subordinate and end entity certificates used to authenticate IoT devices), rather than to public WebPKI server certificates.
The section focuses on X.509 v3 certificates.

### Version

Certificates MUST be of type X.509 v3.

### Serial Number

The serial number MUST be unique
for each certificate issued by a given CA (i.e., the issuer name
and the serial number uniquely identify a certificate).
{{!RFC5280}} limits this field to a maximum of 20 octets.
To reduce the risk of predictable serial numbers, CAs SHOULD generate serial
numbers containing at least eight (8) octets of unpredictable output from a
cryptographically secure pseudo-random number generator. The random value MAY
be combined with a counter or other information that ensures uniqueness.

### Signature

The signature MUST be ecdsa-with-SHA256 or stronger {{!RFC5758}}.

Note: In contrast to IEEE 802.1AR this specification does not require
end entity certificates, subordinate CA certificates, and CA
certificates to use the same signature algorithm. Furthermore,
this specification does not utilize RSA for use with constrained IoT
devices and networks.
For certificates expected to be validated by constrained IoT devices, CAs
SHOULD select signature algorithms supported by those devices to ensure
successful validation (e.g., ECDSA P-256). Different certificates in the same
chain MAY use different signature algorithms when the relying devices support
validation of the resulting chain.

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
time checks with coarse granularity (e.g., day- or hour-level) and ignore leap
seconds when validating notAfter. For devices without a reliable source of time
this document recommends the use of a device management solution, which
typically includes a certificate management protocol, to manage certificates
used by the device over their lifecycle. While this approach does not utilize
certificates to its widest extent, it is a solution that extends the
capabilities offered by a raw public key approach.

In many IoT deployments, IDevIDs are provisioned with an unlimited lifetime,
as described in {{IEEE-802.1AR}}. This helps prevent devices from being
accidentally bricked due to certificate expiration. A real-world example
occurred in 2018, when Oculus Rift headsets became unusable after an Oculus
certificate expired {{Toms-Hardware-Oculus-Rift-2018}}. Oculus later issued
a manual patch, as the expired certificate also blocked the standard software
update path.

For this purpose, the special GeneralizedTime
value 99991231235959Z is used in the notAfter field, as described in
{{Section 4.1.2.5 of !RFC5280}}. However, the CA certificate and subordinate CA
certificates in the certification path may still have finite validity periods.
Careful consideration is therefore required before issuing IDevID certificates
with no maximum validity period, since an effectively unlimited certificate
lifetime is only useful if the relevant certification path remains usable for
the intended lifetime of the device.
Deployments also need to verify that their CA software and issuance policy
support the intended validity model. Some CA implementations and policies do
not permit subordinate CA certificates or end-entity certificates to outlive
the issuing CA certificate.

LDevID certificates are, however, issued by the operator or owner,
and may be renewed at a regular interval using protocols, such
as Enrollment over Secure Transport (EST) {{?RFC7030}} or
Certificate Management Protocol (CMP) {{-cmp}} {{-lw-cmp}}.
It is therefore RECOMMENDED to limit the lifetime of these LDevID certificates
using the notBefore and notAfter fields, as described in {{Section 4.1.2.5 of
!RFC5280}}. Consistent with {{Section 4.1.2.5.1 of !RFC5280}} and
{{Section 4.1.2.5.2 of !RFC5280}}, values MUST be expressed in Greenwich Mean
Time (Zulu) and MUST include seconds even where the number of seconds is zero.

Note that the validity period is defined as the period of time from notBefore
through notAfter, inclusive. This means that a hypothetical certificate with a
notBefore date of 9 June 2021 at 03:42:01 and a notAfter date of 7 September
2021 at 03:42:01 becomes valid at the beginning of the :01 second, and only
becomes invalid at the :02 second, a period that is 90 days plus 1 second. So
for a 90-day, the time portion of notAfter is 03:42:00.

### Subject Public Key Info

The subjectPublicKeyInfo field indicates the algorithm and any associated
parameters for the ECC public key. This profile uses the id-ecPublicKey
algorithm identifier for ECDSA signature keys, as defined and specified in
{{!RFC5480}}. This specification assumes that devices support one of the
following algorithms:

- id-ecPublicKey with secp256r1,
- id-ecPublicKey with secp384r1, and
- id-ecPublicKey with secp521r1.

TLS 1.3 certificate-based authentication requires end-entity certificates
containing public keys suitable for digital signatures. TLS 1.2 also defined
static DH/ECDH certificate-based key exchange modes in which the end-entity
certificate contains a key-agreement public key rather than a signature public
key. This specification prohibits the use of such static DH/ECDH end-entity
certificates with TLS 1.2.

There is no requirement for CA certificates to use the same algorithm as the
end entity certificate.
Certificates with longer lifetime may well use a cryptographically stronger
algorithm. However, CAs (or their administrators) that issue certificates
intended to be validated by constrained IoT devices SHOULD select algorithms
supported by those devices to ensure successful validation. Longer-lived CA
certificates MAY intentionally use stronger or different algorithms if the
target devices are expected to validate such chains successfully.

### Certificate Revocation Checks

Constrained IoT devices often lack the resources to perform traditional
Certificate Revocation List (CRL) or Online Certificate Status Protocol (OCSP)
checks. Consistent with the guidance in {{Section 4.4.3 of RFC7925}}, neither
OCSP nor CRLs are used by constrained IoT devices during the TLS handshake.

Instead, IoT deployments generally rely on short-lived operational end-entity
certificates, such as LDevID certificates, managed via automated onboarding and
management protocols (such as Lightweight Machine-to-Machine {{LwM2M-T}}
{{LwM2M-C}}).  Because these protocols can
distribute and update certificates on demand, they make real-time revocation
checks largely unnecessary.

Since these checks are bypassed, the CRL Distribution Points extension and
the Authority Information Access (AIA) extension for OCSP SHOULD NOT be
included in IoT device certificates.  If they are present, they MUST NOT be
marked critical.  However, the AIA extension MAY be used to provide the
caIssuer access method, enabling peers with sufficient resources to fetch
certificate chains.

When designing the application layer, developers must account for the fact that
updating a certificate does not automatically affect existing, long-lived TLS
sessions.  TLS alone does not mandate continuous validity checks once a
connection is established.  Furthermore, TLS 1.3 natively supports only
client-to-server post-handshake authentication.  Achieving mutual
post-handshake authentication requires Exported Authenticators
{{?RFC9261}}, which requires the application-layer protocol
to carry the authentication payload.  Therefore, if continuous validation is strictly required
for a long-lived connection, it is the application's responsibility to enforce
this policy by actively triggering re-authentication or tearing down and
re-establishing the TLS session.

Ultimately, instead of attempting to perform revocation checks directly on the
constrained device, it is RECOMMENDED to delegate this responsibility to the
IoT device operator, who can take the necessary administrative actions (such as
deploying updated certificates) to keep the network secure and operational.
While the above recommendation is valid in most cases, it should be considered
carefully on a case-by-case basis, taking into account the security risks
associated with not re-authenticating peers and the cost/complexity of
implementing an application-layer solution.

## Root CA Certificate

This section outlines the requirements for root CA certificates.

### Subject

{{Section 4.1.2.6 of !RFC5280}} requires that, when the subject is a CA,
the subject field be populated with a non-empty distinguished name.
Therefore, Root CA certificates MUST have a non-empty subject field.
This is because a CA's Subject DN becomes the subordinate certificate's Issuer DN, which MUST NOT be empty.
The subject field
MUST contain the commonName, the organizationName, and the countryName
attribute and MAY contain an organizationalUnitName attribute.
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
public key info field.

The subjectKeyIdentifier is used by path construction algorithms to identify which CA has signed a subordinate certificate.

### Key Usage

{{Section 4.2.1.3 of !RFC5280}} defines the key usage field as follows: "The key usage extension defines
the purpose (e.g., encipherment, signature, certificate signing) of the key contained
in the certificate."

The Key Usage extension SHOULD be set in Root CA certificates. If present, it MUST be
marked critical and MUST include keyCertSign. If the CA signs CRLs, cRLSign
MUST also be set. The digitalSignature bit is only needed when the same CA key
is used to sign objects other than certificates or CRLs, such as OCSP responses.

The extension MAY be omitted only in closed deployments where all
relying parties are configured to accept the Root CA certificate as a trust
anchor according to local policy without processing the Key Usage extension.

### Extended Key Usage

{{Section 4.2.1.12 of !RFC5280}} defines the extended key usage as follows: "This extension indicates
one or more purposes for which the certified public key may be used, in addition to
or in place of the basic purposes indicated in the key usage extension."

This extendedKeyUsage extension MUST NOT be set in CA certificates.

### Basic Constraints

{{Section 4.2.1.9 of !RFC5280}} states that "The Basic Constraints extension identifies whether the subject
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

Omitting pathLenConstraint follows common root CA practice but is not meant to
encourage arbitrarily deep certification hierarchies in IoT deployments.
Shallow hierarchies remain preferable for constrained devices.

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

{{Section 4.2.1.3 of !RFC5280}} defines the key usage extension. The Key Usage
extension MUST be set, MUST be marked critical, and the keyCertSign purpose MUST
be set. If the subordinate CA issues CRLs, the cRLSign purpose MUST also be set.
The digitalSignature purpose SHOULD be set.

Subordinate certification authorities SHOULD NOT have any extendedKeyUsage.
{{Section 4.2.1.12 of !RFC5280}} reserves EKUs to be meaningful only in end
entity certificates.

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

This section describes the use of end entity certificates primarily for (D)TLS
clients running on IoT devices. Operating (D)TLS servers on IoT devices is
possible but less common.

{{!RFC9525, Section 2}} mandates that the subject field not be used to identify a service.
However, certain IoT applications (for example, {{?I-D.ietf-anima-constrained-voucher}},
{{IEEE-802.1AR}}) use the subject field to encode the device serial number.

This specification removes the requirement in {{Section 4.4.2 of !RFC7925}} that stipulated
the exclusive use of EUI-64 in the subject field of end entity certificates.

Two fields are typically used to encode a device identifier, namely the
Subject and the subjectAltName fields. Protocol specifications tend to offer
recommendations about what identifiers to use and the deployment situation is
fragmented.

It is common to use serial numbers as identifiers for IoT devices, but the
term "serial number" is overloaded. This profile distinguishes between a
manufacturer-assigned device serial number and a link-layer identifier such as
an EUI-48, EUI-64, or MAC address.

A manufacturer-assigned device serial number is an identifier assigned to a
device by its manufacturer. When this identifier is included in the certificate
subject distinguished name (Subject DN), {{Appendix A.1 of !RFC5280}} provides
the X520SerialNumber attribute:

~~~~
id-at-serialNumber   OBJECT IDENTIFIER ::= { id-at 5 }
X520SerialNumber    ::= PrintableString
~~~~

This value is part of the Subject DN. Section 8.6 of {{IEEE-802.1AR}} mandates
that the Subject DN is not null and encourages use of
the X520SerialNumber attribute as the primary name for the device.

An EUI-48 or EUI-64 identifies a link-layer interface or, depending on the
allocation scheme, a device. It has defined binary semantics and is not
inherently the same concept as a manufacturer's product serial number. A
deployment may use an EUI-64 as its device serial number, but that does not
make the concepts identical. A device serial number can be an arbitrary
manufacturer-defined string, while a device can have multiple MAC addresses,
and those addresses can change when interfaces are replaced or reconfigured.
Many constrained IoT devices, however, do not have more than one network
interface; for those devices it can be convenient for manufacturers to reuse an
existing unique MAC address or EUI as the device identifier.

{{Section 4.4.2 of !RFC7925}} requires the identifier in a client certificate
to be an EUI-64 and permits that identifier to appear either in the
subjectAltName or in the leftmost commonName component of the Subject DN. This
profile updates that guidance by distinguishing manufacturer-assigned device
serial numbers from EUI-48 and EUI-64 link-layer identifiers.

{{Section 2.3.1 of ?RFC8995}} uses a device serial number to identify a BRSKI
pledge. Consistent with {{IEEE-802.1AR}}, {{?RFC8995}} identifies the device
serial-number field as the X520SerialNumber attribute defined in
{{Appendix A.1 of !RFC5280}}. The registrar extracts this certified device
serial number from the pledge's IDevID and uses it in voucher processing. The
important semantic point is that BRSKI needs a stable manufacturer device
identifier; {{?RFC8995}} does not require this value to be an EUI-48 or EUI-64.

A manufacturer-assigned device serial number included in the Subject DN MUST be
encoded in the X520SerialNumber attribute. If an EUI-48 or EUI-64 is used to
identify a device, it SHOULD be encoded in the subjectAltName extension using
the MACAddress otherName defined in {{I-D.ietf-lamps-macaddress-on}}. An
EUI-64 that serves as the manufacturer-assigned device serial number MAY
instead be encoded in the X520SerialNumber attribute.

{{!RFC5280}} defines: "The subject alternative name extension allows identities
to be bound to the subject of the certificate. These identities may be included
in addition to or in place of the identity in the subject field of the certificate."

The subject alternative name extension MAY be set. If it is set, it MUST NOT be
marked critical, except when the subject DN contains an empty sequence.

The MACAddress otherName carries the value as an OCTET STRING. An EUI-48 is
encoded as exactly 6 octets and an EUI-64 is encoded as exactly 8 octets.
{{I-D.ietf-lamps-macaddress-on}} also defines how this name form is used with
the {{!RFC5280}} Name Constraints extension, allowing a CA certificate to
constrain permitted or excluded MAC address ranges, for example by an
Organizationally Unique Identifier (OUI).

The CA needs to validate the identifier's relationship to the subject. For a
MACAddress value, {{I-D.ietf-lamps-macaddress-on}} requires the CA to ensure
that the address is owned by, or expected to be owned by, the subject device for
the certificate's lifetime. This requirement can be difficult for replaceable
interfaces, virtual interfaces, locally administered addresses, and MAC address
randomization.

Both manufacturer-assigned device serial numbers and EUI-48 or EUI-64 values
can expose stable identifiers to certificate recipients. TLS 1.3 better
protects client certificates against passive observers than earlier TLS
versions because the client certificate is encrypted and sent only after the
server certificate has been received and validated. The authenticated peer,
however, still learns the identifier. An EUI-48 or EUI-64 can reveal
organizational allocation information and can enable correlation across
networks or application contexts. A stable device serial number has similar
correlation risks. Environments that are concerned about such traffic analysis
SHOULD avoid using stable, globally identifiable device identifiers in
operational certificates. This can be achieved, for example, by using an enrollment
protocol to migrate from identifiable IDevID certificates to less identifiable
operational LDevID certificates, or by provisioning operational certificates
that contain only deployment-local or otherwise non-public identifiers.

Per {{!RFC9525}} domain names MUST NOT be encoded in the subject commonName. Instead they
MUST be encoded in a subjectAltName of type DNS-ID. Domain names MUST NOT
contain wildcard (`*`) characters. The subjectAltName MUST NOT contain multiple
names.

Note: The IEEE 802.1AR recommends to encode information about a Trusted
Platform Module (TPM), if present, in the HardwareModuleName ({{Section 5 of ?RFC4108}}). This
specification does not follow this recommendation.


### Authority Key Identifier

The Authority Key Identifier extension MUST be set, MUST NOT be marked critical,
and MUST contain the subjectKeyIdentifier of the CA that issued this certificate.

### Subject Key Identifier

The Subject Key Identifier MUST NOT be included in end entity certificates, as it can be calculated from the public key, so it just takes up space.
End entity certificates are not used in path construction, so there is no ambiguity regarding which certificate chain to use, as there can be with subordinate CAs.

### Key Usage

The key usage extension MUST be set and MUST be marked as critical. For
signature verification keys the digitalSignature key usage purpose MUST
be specified. Other key usages are set according to the intended usage
of the key.

As specified in {{IEEE-802.1AR}}, the extendedKeyUsage SHOULD NOT be present in
IDevID certificates, as it reduces the utility of the IDevID.
For locally assigned LDevID certificates to be usable with TLS,
the extendedKeyUsage MUST contain at least one of the following:
id-kp-serverAuth or id-kp-clientAuth. The selected EKUs MUST match the
intended TLS role of the device or service using the certificate.

# Update of Trust Anchors
{: #trust_anchor_update}

Since the publication of RFC 7925 the need for firmware update mechanisms
has been reinforced and the work on standardizing a secure and
interoperable firmware update mechanism has made substantial progress,
see {{?RFC9019}}. RFC 7925 recommends to use a software / firmware update
mechanism to provision devices with new trust anchors. This approach only
addresses the distribution of trust anchors and not end entity certificates
or certificates of subordinate CAs.

Trust-anchor lifecycle management is central to IoT certificate profiles.
IoT devices, especially in industrial deployments, often remain in service for
many years and may operate in environments where physical access is expensive
or impossible. A certificate profile that assumes static trust anchors for the
entire device lifetime makes algorithm transitions, CA rollover, manufacturer
changes, and incident response significantly harder.

As an alternative, certificate management protocols like CMP and EST
have also offered ways to update trust anchors. See, for example,
{{Section 2.1 of ?RFC7030}} for an approach to obtaining CA certificates
via EST.

# Certificate Overhead
{: #certificate_overhead}

In certificate-based authentication, certificates and public keys are a major
contributor to the size of the overall handshake. For example, in a regular TLS
1.3 handshake with minimal ECC certificates and no subordinate CA using
the secp256r1 curve with mutual authentication, around 40% of the entire
handshake payload is consumed by the two exchanged certificates.

Deployments should first apply the certificate-profile recommendations in this
document, since they reduce both bandwidth use and certificate processing cost
without requiring additional TLS extensions:

* Use elliptic curve cryptography (ECC) instead of RSA-based certificates. This
  document recommends the use of elliptic curve cryptography only.
* Avoid deep and complex CA hierarchies to reduce the number of subordinate CA
  certificates that need to be transmitted and processed. See
  {{?I-D.irtf-t2trg-taxonomy-manufacturer-anchors}} for a discussion about CA
  hierarchies. Most security requirements can be satisfied with a PKI depth of
  3 (root CA, one subordinate CA, and end entity certificates).
* Include only the certificate fields and extensions needed for the intended
  deployment. The profile in {{certificate_profile}} identifies certificate
  content that can be omitted in constrained IoT deployments.
* Transmit only the certificates needed by the peer to build a path to one of
  its configured trust anchors. Trust anchors are intended to be provisioned
  out of band and a trust anchor received in a TLS Certificate message cannot
  be assumed trustworthy. A trust anchor therefore SHOULD NOT be included in
  the Certificate message.

TLS and DTLS also provide mechanisms that reduce how often large certificate
chains have to be exchanged. Session resumption reduces the size of subsequent
handshakes after an initial authenticated exchange. DTLS Connection IDs
{{RFC9146}}, when applicable, help preserve long-lived associations across
address or path changes and can therefore avoid handshakes that would otherwise
be needed to re-establish the connection.

Omitting trust anchors from the Certificate message is the preferred baseline,
but the sender still has to provide enough information for the peer to validate
the presented end entity certificate. In some deployments the sender cannot
infer which trust anchor the peer has configured. For example, the peer's trust
anchor might be an intermediate CA rather than a root CA, or a root key
transition might mean that different devices have different old or new trust
anchors installed. In these cases, the peer MAY use the "certificate_authorities"
extension to indicate the CAs which an endpoint supports,
see {{Section 4.3.4 of -TLS13}}, to help the sender select an appropriate certificate
chain. During trust-anchor updates, deployments may also need transitional
cross-certificates, such as the newWithOld and oldWithNew certificates
described by {{Section 4.4 of -cmp}}. Such certificates can help bridge the
transition, but they do not replace out-of-band provisioning of trust anchors.

Additional techniques are available, but they are more deployment-specific and
are not uniformly supported by TLS/DTLS stacks:

* Certificate compression {{?RFC8879}} can reduce the size of certificates
  that still have to be transmitted. Related guidance for IoT deployments is
  provided by {{?RFC9191}}.
* Server certificate caching can reduce retransmission when a client repeatedly
  connects to the same server, which is a common IoT deployment scenario.
  The TLS cached info {{?RFC7924}} extension defines such a mechanism.
  {{?RFC7924}} was written for TLS/DTLS 1.2 and describes the server response
  in ServerHello. In TLS 1.3, the client offers `cached_info` in ClientHello
  and the server confirmation is carried in EncryptedExtensions
  ({{Section 4.3.1 of -TLS13}}). {{?RFC7924}} defines cached information types
  for server Certificate messages and server CertificateRequest messages. It
  does not define caching of client Certificate messages.

  For TLS 1.3, the server Certificate message includes a
  `certificate_request_context` field. For server authentication, this field is
  zero length ({{Section 4.4.2 of -TLS13}}), so it does not by itself prevent
  server certificate information from being cached.

  The CertificateRequest message also includes a
  `certificate_request_context` field. For client authentication in the main
  handshake, this field is zero length unless post-handshake authentication is
  used ({{Section 4.3.2 of -TLS13}}). Consequently, caching
  CertificateRequest messages can still be applicable when the server's
  client-authentication request parameters are large and stable. The
  potentially large parts are the extensions in CertificateRequest, especially
  the `certificate_authorities` extension, which lists distinguished names of
  acceptable CAs ({{Section 4.2.4 of -TLS13}}). In many IoT deployments, unlike
  WebPKI-style deployments, this list is small or omitted because only a small
  number of trust anchors is used. In contrast,
  CertificateRequest caching is not useful for post-handshake authentication
  since the `certificate_request_context` changes between requests.
* The client certificate URL mechanism defined in {{Section 5 of RFC6066}} can
  replace client certificates in the handshake with references to external
  certificate objects. When
  applications perform TLS client authentication via DNS-Based Authentication
  of Named Entities (DANE) TLSA records, then the DANE Client Identity TLS extension
  {{?I-D.ietf-dance-client-auth}} may be used to reduce the packets on the
  wire. The term "TLSA" does not stand for anything; it is the name of the
  RRtype, as explained in {{?RFC6698}}.
* Alternative certificate formats, such as raw public keys {{RFC7250}} or
  CBOR-encoded certificates {{?I-D.ietf-cose-cbor-encoded-cert}}, can reduce
  credential size where the application and provisioning model support them.
* Certificate handles, where available, are another form of caching.

These additional mechanisms can be useful, but they can also introduce side
effects, such as reliance on DNS or directory infrastructure, cache
invalidation requirements, privacy exposure to retrieval services, changes to
the credential provisioning model, and additional implementation code. A
deployment SHOULD first prefer mechanisms with broad TLS/DTLS 1.3 support and
low operational complexity: compact certificate profiles, shallow certification
paths, omitting trust anchors from the handshake, session resumption, DTLS
Connection IDs, and certificate compression. More deployment-specific mechanisms
such as cached certificate information, certificate URLs, DANE client identity,
or certificate handles SHOULD be used only when their operational dependencies,
cache invalidation behavior, and privacy impact are acceptable for the
deployment.

# Ciphersuites {#ciphersuites}

According to {{Section 4.5.3 of -DTLS13}}, the use of AES-CCM with 8-octet
authentication tags (CCM_8) is considered unsuitable for general use with DTLS.
This is because it has low integrity limits (i.e., high sensitivity to
forgeries) which makes endpoints that negotiate ciphersuites based on such AEAD
vulnerable to a trivial DoS attack. See also {{Sections 5.3 and 5.4 of
?I-D.irtf-cfrg-aead-limits}} for further discussion on this topic, as well as
references to the analysis supporting these conclusions.

Specifically, {{-DTLS13}} warns that:

{: quote}
> TLS_AES_128_CCM_8_SHA256 MUST NOT be used in DTLS without additional
> safeguards against forgery. Implementations MUST set usage limits for
> AEAD_AES_128_CCM_8 based on an understanding of any additional forgery
> protections that are used.

Since all the ciphersuites required by {{RFC7925}} and {{CoAP}} rely on CCM_8,
there is no alternate ciphersuite available for applications that aim to
eliminate the security and availability threats related to CCM_8 while retaining
interoperability with the larger ecosystem.

In order to ameliorate the situation, it is RECOMMENDED that
implementations support the following two ciphersuites for TLS 1.3:

* `TLS_AES_128_GCM_SHA256`
* `TLS_AES_128_CCM_SHA256`

and offer them as their first choice.  These ciphersuites provide
confidentiality and integrity limits that are considered acceptable in the most
general settings.  For the details on the exact bounds of both ciphersuites see
{{Section 4.5.3 of -DTLS13}}.  Note that the GCM-based ciphersuite offers
superior interoperability with cloud services at the cost of a slight increase
in the wire and peak RAM footprints.

TLS 1.3 enforces deterministic nonce generation for all AEAD cipher suites.
However, this is not the case for TLS 1.2.
Therefore, when using the GCM-based cipher suite with TLS 1.2, the recommendations in {{Section 7.2.1 of !RFC9325}} relating to deterministic nonce generation apply.
In addition, the integrity limits on key usage detailed in {{Section 4.4 of !RFC9325}} also apply.

{{tab-cipher-reqs}} summarizes the recommendations regarding ciphersuites:

| Ciphersuite | Requirement |
|--|--|
| `TLS_AES_128_CCM_8_SHA256` | MUST implement for compatibility with {{RFC7925}} and {{CoAP}} deployments; not recommended for new deployments |
| `TLS_AES_128_CCM_SHA256` | SHOULD implement |
| `TLS_AES_128_GCM_SHA256` | SHOULD implement |
{: #tab-cipher-reqs align="left" title="TLS 1.3 Ciphersuite Requirements"}

# Post-Quantum Cryptography (PQC) Considerations

The recommendations and ciphersuites in this profile are based on classical
cryptography and are not quantum-resistant.

Guidance for using post-quantum cryptography with application protocols,
including TLS, is provided by {{?I-D.ietf-uta-pqc-app}}. That document is the
primary source of PQC deployment recommendations for applications and
constrained environments. It discusses algorithm selection, migration planning,
and the operational impact of larger key shares, public keys, signatures, and
certificates.

PQC transition planning is especially relevant for IoT devices because product
lifetimes are long and device constraints limit the adoption of larger key
sizes and more complex cryptographic operations {{PQC-PERF}}. Deployments also
need to evaluate the energy impact of PQC choices {{PQC-ENERGY}}. Additional
background for engineers is provided by {{RFC9958}}, and guidance on PQC use
with constrained hardware security modules is provided by
{{?I-D.ietf-pquip-pqc-hsm-constrained}}.

As a transitional measure, {{RFC9973}} allows certificate-based
authentication to be combined with a strong external PSK that is incorporated
into the TLS 1.3 key schedule. This provides confidentiality protection against
a future cryptographically relevant quantum computer, provided that the
external PSK is generated and distributed securely. It does not make the
certificate-based authentication quantum resistant. Deployments can use this
mechanism as a migration path while PQC algorithms for certificate-based
authentication are being introduced.

# Privacy Considerations {#privacy-considerations}

The privacy considerations in {{Section 22 of !RFC7925}} largely continue to
apply. However, compared to TLS 1.2 and DTLS 1.2, TLS 1.3 and DTLS 1.3 encrypt
a larger portion of the handshake, which reduces the amount of identity and
credential metadata observable on the wire by passive attackers. Extensions,
such as the encrypted ClientHello, further increase privacy protection.

Certificate fields can expose stable device identifiers and other metadata.
In particular, IDevIDs and LDevIDs may reveal manufacturer identity, device
serial numbers, or other information to peers. Protection against passive
observers is, however, substantially improved since certificates are encrypted
in TLS 1.3 and DTLS 1.3. Client certificates are also sent only after the server
certificate has been received and validated. The server still
receives the certificate and learns the identifiers it contains.

Manufacturer-assigned device serial numbers and EUI-48 or EUI-64 values can
enable correlation across networks or application contexts. EUI-48 and EUI-64
values can also reveal organizational allocation information. Deployments that
are concerned about such traffic analysis SHOULD use an enrollment protocol to
migrate from identifiable IDevID certificates to less identifiable operational
LDevID certificates. Deployments that continue to use stable identifiers in
certificates expose those identifiers to peers and can enable correlation
across connections, networks, or application contexts.

Some deployments use the mechanisms discussed in the Certificate Overhead section,
such as certificate URLs or external certificate retrieval, instead of always
transmitting full certificates in the handshake. In these cases, the privacy
properties differ because stable identifiers may be exposed to retrieval
services, directories, or to observers of those retrieval transactions.

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

## Fault Attacks on Deterministic Signature Schemes

A number of passive side-channel attacks as well as active fault-injection
attacks (e.g., {{Ambrose2017}}) have been demonstrated to be successful in allowing a malicious
third party to gain information about the signing key if a fully deterministic
signature scheme (e.g., ECDSA {{?RFC6979}} or EdDSA {{?RFC8032}}) is used.

Most of these attacks assume physical access to the device and are therefore
especially relevant to smart cards as well as IoT deployments with poor or
non-existent physical security.

It is therefore recommended to introduce randomness into the signature scheme,
as in the original ECDSA specification, or to combine deterministic and
randomized techniques, for example as described in
{{?I-D.irtf-cfrg-det-sigs-with-noise}}. However, the use of randomized
signature algorithms can make implementations more difficult to test,
as discussed in {{?RFC6979}}.

## Authentication- and Integrity-Only Cipher Suites

{{?RFC9150}} defines TLS 1.3 cipher suites that provide authentication and
message integrity without confidentiality. {{?RFC9150}} limits their
applicability to cases where confidentiality and privacy requirements are
absent or explicitly relaxed, but authenticity and integrity are still
required; examples include industrial automation commands, fine-grained time
updates, alarms, railway control, and safety-related recording or inspection.
These cipher suites are not general-purpose TLS cipher suites.

Deployments need an application-specific safety, security, and privacy analysis
and need to verify that the application protocol and application data do not
rely on confidentiality. This document leaves such profiling to (industrial)
IoT deployments and therefore does not specify authentication- or integrity-only
cipher suites.

# IANA Considerations

This document makes no requests to IANA.

--- back

# Acknowledgments
{:unnumbered}

We would like to thank
Henk Birkholz,
Hendrik Brockhaus,
Roman Danyliw,
Menachem Dodge,
Martin Duke,
Gorry Fairhurst,
Miek Gieben,
Russ Housley,
Ben Kaduk,
Achim Kraus,
John Mattsson,
Tiru Reddy,
Scott Rose,
Rich Salz,
Mohit Sethi,
Ketan Talaulikar,
Martin Thomson,
Marco Tiloca, and
Éric Vyncke.

Finally, we would like to thank our security area director Deb Cooley for her detailed review comments.
