"""Python bindings for the XML Security Library.

The C extension lives at ``xmlsec._impl`` and now exposes the
cryptographic operations as bytes-in / bytes-out entry points
(``_sign_doc`` and friends). This package owns the lxml↔bytes bridge so
no xmlNodePtr ever crosses between lxml's libxml2 and python-xmlsec's
libxml2 — the design fix for issue #356.
"""

from __future__ import annotations

import sys as _sys

from lxml import etree
from lxml.etree import _Element

from xmlsec import _bridge, _impl, template, tree
from xmlsec._impl import (
    EncryptionContext,
    Error,
    InternalError,
    Key,
    KeysManager,
    VerificationError,
    __version__,
    base64_default_line_size,
    cleanup_callbacks,
    constants,
    enable_debug_trace,
    get_libxml_compiled_version,
    get_libxml_version,
    get_libxmlsec_version,
    init,
    register_callbacks,
    register_default_callbacks,
    shutdown,
)

# Expose the C-extension submodule ``constants`` under its public dotted name so
# that ``import xmlsec.constants`` resolves to the same module object as
# ``xmlsec._impl.constants``. ``xmlsec.tree`` and ``xmlsec.template`` are now
# Python package modules; no aliasing needed.
_sys.modules.setdefault('xmlsec.constants', constants)


class SignatureContext:
    """XML Digital Signature context.

    A thin Python wrapper around ``xmlsec._impl.SignatureContext``. The
    wrapper owns the lxml↔bytes bridge for ``sign`` / ``verify`` and the
    eager-validation half of ``register_id``; the C extension does the
    cryptography on python-xmlsec's libxml2 alone.
    """

    def __init__(self, manager: KeysManager | None = None) -> None:
        self._impl = _impl.SignatureContext(manager) if manager is not None else _impl.SignatureContext()
        # List of (live element, id_attr, id_ns_or_None, value) entries
        # appended by ``register_id``. Expanded into structural-path id
        # specs at sign/verify time.
        self._id_registrations: list[tuple[_Element, str, str | None, str]] = []

    # --- Properties ---------------------------------------------------------

    @property
    def key(self) -> Key | None:
        return self._impl.key

    @key.setter
    def key(self, value: Key) -> None:
        self._impl.key = value

    @key.deleter
    def key(self) -> None:
        del self._impl.key

    # --- ID registration ---------------------------------------------------

    def register_id(self, node: _Element, id_attr: str = 'ID', id_ns: str | None = None) -> None:
        """Register an XML id attribute on ``node``.

        Validates eagerly (matching the prior C implementation in
        src/ds.c:131-180): raises ``Error("missing attribute.")`` if the
        attribute is absent, ``Error("duplicated id.")`` if a different
        registration with the same value already exists on this context.
        The actual ``xmlAddID`` call is deferred to sign/verify time on
        python-xmlsec's internal libxml2 doc.
        """
        if not etree.iselement(node):
            raise TypeError('node must be lxml.etree._Element')
        if id_ns is not None:
            attr_key = f'{{{id_ns}}}{id_attr}'
        else:
            attr_key = id_attr
        value = node.get(attr_key)
        if value is None:
            raise Error('missing attribute.')

        for existing_node, existing_attr, existing_ns, existing_value in self._id_registrations:
            if existing_value != value:
                continue
            if existing_node is node and existing_attr == id_attr and existing_ns == id_ns:
                return  # exact same registration: no-op (matches xmlGetID == attr in C)
            raise Error('duplicated id.')

        self._id_registrations.append((node, id_attr, id_ns, value))

    def _build_id_specs(self, op_tree) -> list[tuple[list[int], str, str | None]]:  # noqa: ANN001
        """Resolve live id registrations into structural-path specs for the C side.

        Combines per-context ``register_id`` entries with any process-level
        ``tree.add_ids`` registrations that target the same tree. Tree
        identity is checked via root elements: lxml hands back a fresh
        ``_ElementTree`` proxy on every ``getroottree()``, so ``is`` on the
        wrapper would always fail.
        """
        op_root = op_tree.getroot()
        specs: list[tuple[list[int], str, str | None]] = []
        for elem, id_attr, id_ns, _value in self._id_registrations:
            try:
                if elem.getroottree().getroot() is not op_root:
                    continue
            except Exception:  # noqa: BLE001
                continue
            specs.append((_bridge.structural_path(elem), id_attr, id_ns))
        specs.extend(_bridge.expand_tree_id_specs(op_tree))
        return specs

    # --- Sign / verify -----------------------------------------------------

    def sign(self, node: _Element) -> None:
        """Sign according to the signature template at ``node``.

        ``node`` must be a ``<Signature>`` element attached to a tree.
        The doc is serialized, signed inside python-xmlsec's libxml2,
        re-parsed with lxml, and the result is spliced into ``node`` in
        place so the user's reference remains valid.
        """
        if not etree.iselement(node):
            raise TypeError('node must be lxml.etree._Element')
        xml_bytes, base_url = _bridge.serialize(node)
        sig_path = _bridge.structural_path(node)
        id_specs = self._build_id_specs(node.getroottree())
        signed = self._impl._sign_doc(xml_bytes, base_url, sig_path, id_specs)
        new_tree = _bridge.parse(signed, base_url)
        new_node = _bridge.locate(new_tree, sig_path)
        _bridge.replace_in_place(node, new_node)

    def verify(self, node: _Element) -> None:
        """Verify the signature at ``node``.

        Read-only — does not mutate the user's tree. Raises
        ``VerificationError`` if the signature does not match.
        """
        if not etree.iselement(node):
            raise TypeError('node must be lxml.etree._Element')
        xml_bytes, base_url = _bridge.serialize(node)
        sig_path = _bridge.structural_path(node)
        id_specs = self._build_id_specs(node.getroottree())
        self._impl._verify_doc(xml_bytes, base_url, sig_path, id_specs)

    # --- Pass-throughs to the C implementation -----------------------------

    def sign_binary(self, bytes: bytes, transform) -> bytes:  # noqa: A002, ANN001
        return self._impl.sign_binary(bytes, transform)

    def verify_binary(self, bytes: bytes, transform, signature: bytes) -> None:  # noqa: A002, ANN001
        self._impl.verify_binary(bytes, transform, signature)

    def enable_reference_transform(self, transform) -> None:  # noqa: ANN001
        self._impl.enable_reference_transform(transform)

    def enable_signature_transform(self, transform) -> None:  # noqa: ANN001
        self._impl.enable_signature_transform(transform)

    def set_enabled_key_data(self, keydata_list) -> None:  # noqa: ANN001
        self._impl.set_enabled_key_data(keydata_list)


__all__ = [
    'EncryptionContext',
    'Error',
    'InternalError',
    'Key',
    'KeysManager',
    'SignatureContext',
    'VerificationError',
    '__version__',
    'base64_default_line_size',
    'cleanup_callbacks',
    'constants',
    'enable_debug_trace',
    'get_libxml_compiled_version',
    'get_libxml_version',
    'get_libxmlsec_version',
    'init',
    'register_callbacks',
    'register_default_callbacks',
    'shutdown',
    'template',
    'tree',
]
