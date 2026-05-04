"""Python bindings for the XML Security Library.

The C extension lives at ``xmlsec._impl`` and now exposes the
cryptographic operations as bytes-in / bytes-out entry points
(``_sign_doc`` and friends). This package owns the lxml↔bytes bridge so
no xmlNodePtr ever crosses between lxml's libxml2 and python-xmlsec's
libxml2 — the design fix for issue #356.
"""

from __future__ import annotations

import copy
import sys as _sys

from lxml import etree
from lxml.etree import _Element

from xmlsec import _bridge, _impl, template, tree
from xmlsec._impl import (
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


# XMLEnc namespace href and the two recognized Type values for encrypt_xml.
_ENC_NS = 'http://www.w3.org/2001/04/xmlenc#'
_TYPE_ENC_ELEMENT = _ENC_NS + 'Element'
_TYPE_ENC_CONTENT = _ENC_NS + 'Content'


class EncryptionContext:
    """XML Encryption context.

    Python wrapper around ``xmlsec._impl.EncryptionContext``. Owns the
    lxml↔bytes bridge for ``encrypt_binary``, ``encrypt_uri``, and
    ``encrypt_xml``; ``decrypt`` is still C-resident and migrates in a
    later PR.
    """

    def __init__(self, manager: KeysManager | None = None) -> None:
        self._impl = _impl.EncryptionContext(manager) if manager is not None else _impl.EncryptionContext()

    # --- Properties --------------------------------------------------------

    @property
    def key(self) -> Key | None:
        return self._impl.key

    @key.setter
    def key(self, value: Key) -> None:
        self._impl.key = value

    @key.deleter
    def key(self) -> None:
        del self._impl.key

    # --- Encryption operations --------------------------------------------

    def encrypt_binary(self, template: _Element, data: bytes | str) -> _Element:
        """Encrypt ``data`` according to ``template``; mutate ``template`` in place."""
        if not etree.iselement(template):
            raise TypeError('template must be lxml.etree._Element')
        if isinstance(data, str):
            data_bytes = data.encode('utf-8')
        elif isinstance(data, (bytes, bytearray)):
            data_bytes = bytes(data)
        else:
            raise TypeError('data must be bytes or str')
        fragment = etree.tostring(template)
        result_bytes = self._impl._encrypt_binary(fragment, data_bytes)
        new_template = etree.fromstring(result_bytes)
        _bridge.replace_in_place(template, new_template)
        return template

    def encrypt_uri(self, template: _Element, uri: str) -> _Element:
        """Encrypt the contents of ``uri`` into ``template``; mutate ``template`` in place."""
        if not etree.iselement(template):
            raise TypeError('template must be lxml.etree._Element')
        if not isinstance(uri, str):
            raise TypeError('uri must be a string')
        fragment = etree.tostring(template)
        result_bytes = self._impl._encrypt_uri(fragment, uri)
        new_template = etree.fromstring(result_bytes)
        _bridge.replace_in_place(template, new_template)
        return template

    def encrypt_xml(self, template: _Element, node: _Element) -> _Element:
        """Encrypt ``node`` into ``template``; return the new ``<EncryptedData>``.

        The ``Type`` attribute on ``template`` decides whether ``node``
        itself (``...xmlenc#Element``) or its content
        (``...xmlenc#Content``) is encrypted. Mirrors the existing
        ``EncryptionContext.encrypt_xml`` API exactly: for
        ``Type=Element`` the user's ``node`` reference is detached
        (replaced by ``<EncryptedData>`` in its parent); for
        ``Type=Content`` ``node``'s content is replaced in place.
        """
        if not etree.iselement(template) or not etree.iselement(node):
            raise TypeError('template and node must be lxml.etree._Element')

        type_attr = template.get('Type')
        if type_attr not in (_TYPE_ENC_ELEMENT, _TYPE_ENC_CONTENT):
            raise Error('unsupported `Type`, it should be `element` or `content`')

        node_doc_bytes, base_url = _bridge.serialize(node)
        node_path = _bridge.structural_path(node)

        # Decide attached vs detached by comparing root elements (lxml's
        # _ElementTree is a fresh proxy each call so identity comparison
        # of the wrappers always fails).
        node_root = node.getroottree().getroot()
        try:
            template_root = template.getroottree().getroot()
        except Exception:  # noqa: BLE001
            template_root = None

        if template_root is node_root:
            template_path = _bridge.structural_path(template)
            template_bytes_obj = None
        else:
            template_path = None
            template_bytes_obj = etree.tostring(template)

        result_bytes = self._impl._encrypt_xml(
            node_doc_bytes,
            base_url,
            template_path if template_path is not None else None,
            node_path,
            template_bytes_obj if template_bytes_obj is not None else None,
        )

        new_tree = _bridge.parse(result_bytes, base_url)
        post_op = _bridge.locate(new_tree, node_path)

        parent = node.getparent()
        if type_attr == _TYPE_ENC_ELEMENT:
            # node is replaced by <EncryptedData> in its parent slot.
            new_enc = copy.deepcopy(post_op)
            if parent is None:
                node.getroottree()._setroot(new_enc)
            else:
                parent.replace(node, new_enc)
            return new_enc
        else:
            # Type=Content: node stays, its content is replaced.
            _bridge.replace_in_place(node, post_op)
            # Return the <EncryptedData> child of node.
            for child in node:
                return child
            raise InternalError('encrypt_xml(Type=Content) produced no EncryptedData child')

    def decrypt(self, node: _Element) -> _Element | bytes:
        """Decrypt ``node``. Returns either bytes or an lxml ``_Element``."""
        return self._impl.decrypt(node)

    def reset(self) -> None:
        self._impl.reset()


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
