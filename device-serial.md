# Device Identifiers in X.509 Certificates

This note compares the different approaches for encoding device serial
numbers, EUI-48 identifiers, and EUI-64 identifiers in X.509 certificates. It
also explains the relationship between RFC 5280, RFC 7925, RFC 8995, and
`draft-ietf-lamps-macaddress-on`.

## Three Different Kinds of Serial Number

The term "serial number" is overloaded. The following values need to be
distinguished:

1. **Certificate serial number**

   This is the `serialNumber` field in `TBSCertificate`, defined in
   Section 4.1.2.2 of RFC 5280 as `CertificateSerialNumber`. It is assigned by
   the CA and, together with the issuer name, uniquely identifies a
   certificate. It identifies the certificate, not the device.

2. **Device or manufacturer serial number**

   This is an identifier assigned to a device by its manufacturer. When it is
   placed in the certificate subject distinguished name, RFC 5280 provides the
   `X520SerialNumber` attribute:

   ```
   id-at-serialNumber   OBJECT IDENTIFIER ::= { id-at 5 }
   X520SerialNumber    ::= PrintableString
   ```

   This value is part of the `subject` DN. RFC 5280 defines the attribute and
   its syntax, but it does not require every device certificate to contain it,
   nor does it define an EUI-48 or EUI-64 as its required value.
   {{IEEE-802.1AR}} mandates that the SubjectDN not be null (Section 8.6), encouraging the use of the    X520SerialNumber is the primary name for the device.

3. **MAC address or extended unique identifier**

   An EUI-48 or EUI-64 identifies a link-layer interface or, depending on the
   allocation scheme, a device. It has defined binary semantics and is not
   inherently the same thing as a manufacturer's product serial number.

A deployment may use an EUI-64 as its device serial number. That does not make
the concepts identical. A device serial number can be an arbitrary
manufacturer-defined string, while a device can have multiple MAC addresses
and those addresses can change when interfaces are replaced or reconfigured.

## RFC 5280: General Certificate Building Blocks

RFC 5280 provides both relevant certificate locations:

- The `subject` field is a distinguished name composed of attributes. Appendix
  A.1 defines `X520SerialNumber`, with OID `2.5.4.5`, as one such naming
  attribute.
- The `subjectAltName` extension can contain different `GeneralName` forms,
  including `otherName`. An `otherName` is identified by an OID and can carry
  a separately defined ASN.1 value.

RFC 5280 therefore supplies the generic mechanisms, but it does not establish
a universal mapping between a device serial number, an EUI-48, an EUI-64, and
one of these certificate fields.

## RFC 7925: EUI-64 as the Client Identifier

Section 4.4.2 of RFC 7925 requires the identifier in a client certificate to be
an EUI-64. It permits that identifier to appear in either:

- the `subjectAltName`; or
- the leftmost `commonName` component of the subject DN.

RFC 7925 does not specify which `GeneralName` form is used in the
`subjectAltName`. It also does not use or require `X520SerialNumber` for this
purpose.

This leaves two problems:

- An EUI-64 is not a DNS name, URI, IP address, or one of the other
  pre-existing, naturally applicable `GeneralName` forms.
- Encoding the EUI-64 in `commonName` gives a link-layer identifier the
  semantics of a generic DN string and conflicts with the modern practice of
  not using `commonName` for service identity.

This TLS/DTLS 1.3 IoT profile lifts the RFC 7925 requirement that every
end-entity identifier be an EUI-64. It nevertheless states that, when an
EUI-64 is used, it must be encoded in the subject DN as
`X520SerialNumber`. That rule is a profiling decision made by this document;
it is not a requirement inherited from RFC 7925.

## RFC 8995: Manufacturer Device Serial Number

Section 2.3.1 of RFC 8995 uses a device serial number to identify a BRSKI
pledge. 

Consistent with {{IEEE-802.1AR}}, RFC 8995 identifies the device serial-number field as the
`X520SerialNumber` attribute defined in Appendix A.1 of RFC 5280. The registrar
extracts this certified device serial number from the pledge's IDevID and uses
it in voucher processing.

The important semantic point is that BRSKI needs a stable manufacturer device
identifier. RFC 8995 does not require this value to be an EUI-48 or EUI-64.
For example, it can be a manufacturer-assigned value such as `WI-3005`.

The BRSKI approach is therefore:

- **Meaning:** manufacturer or device serial number
- **Location:** subject distinguished name
- **Attribute:** `X520SerialNumber`
- **Encoding:** `PrintableString`
- **Primary use:** stable device identity and correlation with manufacturing
  and voucher records

## MACAddress otherName: Typed EUI-48 and EUI-64 Values

{{!I-D.ietf-lamps-macaddress-on}} defines a dedicated
`GeneralName.otherName` form named `MACAddress`. 

The value is carried in the `subjectAltName` extension as an `OCTET STRING`:

- an EUI-48 is encoded as exactly 6 octets;
- an EUI-64 is encoded as exactly 8 octets.

For example, the textual EUI-48 value `00-24-98-7B-19-02` is represented by
the six bytes `00 24 98 7B 19 02`. Comparisons are byte-for-byte; no wildcard
matching is defined.

The draft also defines how this name form is used with the RFC 5280 Name
Constraints extension. This allows a CA certificate to constrain permitted or
excluded MAC address ranges, for example by an Organizationally Unique
Identifier (OUI).

The MACAddress approach is:

- **Meaning:** EUI-48 or EUI-64 link-layer identifier
- **Location:** `subjectAltName`
- **Name form:** `GeneralName.otherName`
- **Encoding:** 6- or 8-octet `OCTET STRING`
- **Primary use:** binding a link-layer interface identifier to the certified
  public key

## Comparison

| Property | X520SerialNumber | MACAddress otherName |
| --- | --- | --- |
| Semantic type | Manufacturer or device serial number | EUI-48 or EUI-64 |
| Certificate location | Subject DN | Subject Alternative Name |
| ASN.1 representation | `PrintableString` | `OCTET STRING` |
| Identifier length | Variable | Exactly 6 or 8 octets |
| Standard source | RFC 5280; profiled by RFC 8995 | `draft-ietf-lamps-macaddress-on` |
| Name Constraints support | DN constraints apply to the complete directory name | Dedicated MAC/EUI constraint processing |
| Typical stability | Usually intended to remain stable for the device lifetime | May identify a particular interface |
| Multiple values | Multiple DN attributes are technically possible but generally undesirable | SAN can represent multiple interfaces, subject to the certificate profile |
| Human readability | Directly printable | Usually rendered in hexadecimal form |

Neither encoding universally replaces the other because they represent
different kinds of identity:

- Use `X520SerialNumber` when the certificate carries the manufacturer's
  stable device serial number, including when that serial number happens to
  use an EUI-64-shaped string.
- Use `MACAddress otherName` when the certificate asserts that a particular
  EUI-48 or EUI-64 belongs to the subject device or one of its interfaces.

If the same EUI-64 is deliberately used for both purposes, a profile must
decide whether it is encoded once, encoded in both fields, or treated as only
one of the two semantic identifiers. Encoding the value in both fields creates
duplication and requires rules for handling mismatches.

## Consequences for the TLS/DTLS IoT Profile

The current statement that every EUI-64 identifier must be encoded as
`X520SerialNumber` excludes the typed `MACAddress otherName` representation.
It also conflates two cases:

1. an EUI-64 used as a manufacturer's stable device serial number; and
2. an EUI-64 used as a link-layer interface identifier.

The profile should permit the representation appropriate to the intended
semantics. One possible formulation is:

> A manufacturer-assigned device serial number included in the Subject DN
> MUST be encoded in the X520SerialNumber attribute. If an EUI-48 or EUI-64 is
> included as a link-layer identifier, it SHOULD be encoded in the
> subjectAltName using the MACAddress otherName defined in
> draft-ietf-lamps-macaddress-on. An EUI-64 that serves as the
> manufacturer-assigned device serial number MAY instead be encoded in the
> X520SerialNumber attribute.

The final normative language should also decide:

- whether `MACAddress otherName` is a `MUST`, `SHOULD`, or `MAY`;
- whether the legacy `X520SerialNumber` encoding of an EUI-64 remains
  permitted for compatibility;
- whether the same identifier may appear in both fields;
- what a relying party does if both fields are present but differ;
- whether certificates may contain several MACAddress values for
  multi-interface devices; and
- whether interface replacement, MAC randomization, or locally administered
  addresses are within scope.

## Privacy and Lifecycle Considerations

Both approaches can expose stable identifiers to certificate recipients.
TLS 1.3 encrypts certificates during the handshake against passive on-path
observers, but the peer still learns the identifier.

An EUI-48 or EUI-64 can reveal organizational allocation information and can
enable correlation across networks or application contexts. 
A stable device serial number has similar correlation risks. 
Environments that are concerned about such traffic analysis SHOULD use an enrollment protocol
to migrate from identifiable IDevID Certificates to less identifiable (operational) LDevID certificates.

The CA also needs to validate the identifier's relationship to the subject.
For a MACAddress value, the LAMPS draft requires the CA to ensure that the
address is owned by, or expected to be owned by, the subject device for the
certificate lifetime. This requirement can be difficult for replaceable
interfaces, virtual interfaces, locally administered addresses, and MAC
address randomization.

## References

- [RFC 5280: Internet X.509 Public Key Infrastructure Certificate and CRL Profile](https://www.rfc-editor.org/rfc/rfc5280.html)
- [RFC 7925, Section 4.4.2: Certificates Used by Clients](https://www.rfc-editor.org/rfc/rfc7925.html#section-4.4.2)
- [RFC 8995, Section 2.3.1: Identification of the Pledge](https://www.rfc-editor.org/rfc/rfc8995.html#section-2.3.1)
- [draft-ietf-lamps-macaddress-on: Media Access Control Addresses in X.509 Certificates](https://datatracker.ietf.org/doc/draft-ietf-lamps-macaddress-on/)
