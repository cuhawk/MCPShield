"""Authenticate Streamable HTTP peers by their X.509-SVID."""

import re
import ssl
from dataclasses import dataclass

from cryptography import x509
from cryptography.x509.oid import ExtendedKeyUsageOID, ExtensionOID

SPIFFE_ID = re.compile(r"spiffe://[a-z0-9._-]{1,255}(?:/[a-zA-Z0-9._-]+)+")


def valid_spiffe_id(identity):
    return (
        isinstance(identity, str)
        and SPIFFE_ID.fullmatch(identity) is not None
        and all(segment not in {".", ".."} for segment in identity[9:].split("/")[1:])
    )


class PeerVerificationError(ssl.SSLCertVerificationError):
    pass


@dataclass(frozen=True)
class MTLSConfig:
    ca_file: str
    cert_file: str
    key_file: str
    allowed_spiffe_ids: tuple[str, ...]

    def create_context(self):
        verifier = PeerVerifier(self.allowed_spiffe_ids)
        # The exact SPIFFE URI, verified below, is the server identity.
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.load_verify_locations(cafile=self.ca_file)
        context.load_cert_chain(self.cert_file, self.key_file)

        class VerifiedSSLObject(ssl.SSLObject):
            def do_handshake(self):
                super().do_handshake()
                verifier.verify(self.getpeercert(binary_form=True))

        # HTTPX's async transport uses SSLObject via SSLContext.wrap_bio.
        context.sslobject_class = VerifiedSSLObject
        return context


class PeerVerifier:
    def __init__(self, allowed_spiffe_ids):
        self.allowed_spiffe_ids = frozenset(allowed_spiffe_ids)
        if not self.allowed_spiffe_ids or not all(map(valid_spiffe_id, self.allowed_spiffe_ids)):
            raise ValueError("mTLS requires a nonempty allowlist of valid SPIFFE workload IDs")

    def verify(self, certificate_der):
        """Check the leaf of a chain already validated by the TLS handshake."""
        if not certificate_der:
            raise PeerVerificationError("upstream did not present a certificate")
        try:
            certificate = x509.load_der_x509_certificate(certificate_der)
            extensions = certificate.extensions
            san = extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
            key_usage = extensions.get_extension_for_oid(ExtensionOID.KEY_USAGE)
            constraints = extensions.get_extension_for_oid(ExtensionOID.BASIC_CONSTRAINTS)
            try:
                extended_usage = extensions.get_extension_for_oid(ExtensionOID.EXTENDED_KEY_USAGE)
            except x509.ExtensionNotFound:
                extended_usage = None
        except (ValueError, x509.ExtensionNotFound, x509.DuplicateExtension,
                x509.UnsupportedGeneralNameType) as exc:
            raise PeerVerificationError("upstream certificate is missing valid SVID extensions") from exc
        uris = san.value.get_values_for_type(x509.UniformResourceIdentifier)
        usage = key_usage.value
        if (constraints.value.ca or not key_usage.critical or not usage.digital_signature
                or usage.key_cert_sign or usage.crl_sign or (not certificate.subject and not san.critical)
                or len(uris) != 1 or uris[0] not in self.allowed_spiffe_ids):
            raise PeerVerificationError("upstream certificate has no allowed SPIFFE workload identity")
        if extended_usage is not None and not {
            ExtendedKeyUsageOID.SERVER_AUTH, ExtendedKeyUsageOID.CLIENT_AUTH,
        }.issubset(extended_usage.value):
            raise PeerVerificationError("upstream SVID has invalid extended key usage")
        return uris[0]
