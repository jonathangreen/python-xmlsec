"""Pure-Python implementation of ``xmlsec.template``.

Builds XMLDSig (http://www.w3.org/2000/09/xmldsig#) and XMLEnc
(http://www.w3.org/2001/04/xmlenc#) template trees using lxml directly.
This replaces a thin wrapper over libxmlsec's ``xmlSecTmpl*`` family,
which used to dereference lxml-owned xmlNodePtrs and was therefore on
the lxml/xmlsec1 ABI boundary even though it never did any cryptography.

Element ordering, attribute placement, and inter-sibling whitespace are
chosen to match libxmlsec's output byte-for-byte, because the resulting
SignedInfo bytes feed into C14N + digest computation and the existing
test fixtures pin the expected SignatureValue.
"""

from __future__ import annotations

from typing import Sequence

from lxml import etree
from lxml.etree import QName, _Element

from xmlsec import _impl

_consts = _impl.constants
_DSIG_NS = _consts.DSigNs
_ENC_NS = _consts.EncNs

# Common XMLDSig element local names.
_NODE_SIGNATURE = 'Signature'
_NODE_SIGNED_INFO = 'SignedInfo'
_NODE_CANONICALIZATION_METHOD = 'CanonicalizationMethod'
_NODE_SIGNATURE_METHOD = 'SignatureMethod'
_NODE_SIGNATURE_VALUE = 'SignatureValue'
_NODE_REFERENCE = 'Reference'
_NODE_TRANSFORMS = 'Transforms'
_NODE_TRANSFORM = 'Transform'
_NODE_DIGEST_METHOD = 'DigestMethod'
_NODE_DIGEST_VALUE = 'DigestValue'
_NODE_KEY_INFO = 'KeyInfo'
_NODE_KEY_NAME = 'KeyName'
_NODE_KEY_VALUE = 'KeyValue'
_NODE_X509_DATA = 'X509Data'
_NODE_X509_CERTIFICATE = 'X509Certificate'
_NODE_X509_CRL = 'X509CRL'
_NODE_X509_ISSUER_SERIAL = 'X509IssuerSerial'
_NODE_X509_ISSUER_NAME = 'X509IssuerName'
_NODE_X509_SERIAL_NUMBER = 'X509SerialNumber'
_NODE_X509_SUBJECT_NAME = 'X509SubjectName'
_NODE_X509_SKI = 'X509SKI'

# XMLEnc element local names.
_NODE_ENCRYPTED_DATA = 'EncryptedData'
_NODE_ENCRYPTED_KEY = 'EncryptedKey'
_NODE_ENCRYPTION_METHOD = 'EncryptionMethod'
_NODE_CIPHER_DATA = 'CipherData'
_NODE_CIPHER_VALUE = 'CipherValue'
_NODE_INCLUSIVE_NAMESPACES = 'InclusiveNamespaces'

# Duck-typed marker for ``xmlsec.constants.__Transform`` instances.
# TODO: replace this with isinstance(transform, _impl.constants._Transform)
# once the C type is exposed by name; relying on ``tp_name`` is brittle if
# the C extension ever renames the type.
_TRANSFORM_TYPE_NAME = '__Transform'


def _check_element(node: _Element, what: str = 'node') -> None:
    if not etree.iselement(node):
        raise TypeError(f'{what} must be lxml.etree._Element')


def _check_transform(transform: object, what: str = 'transform') -> None:
    if type(transform).__name__ != _TRANSFORM_TYPE_NAME or not hasattr(transform, 'href'):
        raise TypeError(f'{what} must be an xmlsec.constants.__Transform')


def _qname(ns: str | None, name: str) -> QName | str:
    return QName(ns, name) if ns else name


def _child_qname(parent: _Element, ns: str, name: str) -> _Element | None:
    """Return the first direct child matching ns/name, or None."""
    target = f'{{{ns}}}{name}' if ns else name
    for child in parent:
        if child.tag == target:
            return child
    return None


def _add_child(parent: _Element, ns: str | None, name: str, *, nsmap: dict | None = None) -> _Element:
    """Append an element child mirroring libxmlsec's ``xmlSecAddChild``.

    libxmlsec ensures each element child is preceded and followed by a ``\\n``
    text node so the serialized template contains one element per line. We
    replicate that here because the SignedInfo whitespace participates in
    C14N + digest computation, and the existing test fixtures pin the
    SignatureValue against the exact byte layout libxmlsec produces.
    """
    if parent.text is None and len(parent) == 0:
        parent.text = '\n'
    if nsmap is not None:
        child = etree.SubElement(parent, _qname(ns, name), nsmap=nsmap)
    else:
        child = etree.SubElement(parent, _qname(ns, name))
    child.tail = '\n'
    return child


def _add_prev_sibling(node: _Element, ns: str | None, name: str) -> _Element:
    """Insert an element as the previous sibling of ``node``, mirroring ``xmlSecAddPrevSibling``."""
    parent = node.getparent()
    if parent is None:
        raise _impl.Error('node has no parent')
    idx = parent.index(node)
    new = parent.makeelement(_qname(ns, name), {})
    parent.insert(idx, new)
    new.tail = '\n'
    return new


def _set_optional(elem: _Element, attr: str, value: str | None) -> None:
    if value is not None:
        elem.set(attr, value)


# ---------------------------------------------------------------------------
# XMLDSig template builders
# ---------------------------------------------------------------------------

def create(
    node: _Element,
    c14n_method,  # noqa: ANN001 - xmlsec.constants.__Transform
    sign_method,  # noqa: ANN001
    id: str | None = None,
    ns: str | None = None,
) -> _Element:
    """Create a detached ``<Signature>`` template tree.

    Mirrors ``xmlSecTmplSignatureCreateNsPref``. Returns a detached element
    associated logically with ``node``'s document; the caller attaches it.
    """
    _check_element(node)
    _check_transform(c14n_method, 'c14n_method')
    _check_transform(sign_method, 'sign_method')

    if ns:
        nsmap = {ns: _DSIG_NS}
    else:
        nsmap = {None: _DSIG_NS}

    sig = etree.Element(QName(_DSIG_NS, _NODE_SIGNATURE), nsmap=nsmap)
    if id is not None:
        sig.set('Id', id)

    # Build the mandatory inner skeleton: <SignedInfo>, <SignatureValue>.
    signed_info = _add_child(sig, _DSIG_NS, _NODE_SIGNED_INFO)
    c14n = _add_child(signed_info, _DSIG_NS, _NODE_CANONICALIZATION_METHOD)
    c14n.set('Algorithm', c14n_method.href)
    sm = _add_child(signed_info, _DSIG_NS, _NODE_SIGNATURE_METHOD)
    sm.set('Algorithm', sign_method.href)
    _add_child(sig, _DSIG_NS, _NODE_SIGNATURE_VALUE)
    return sig


def add_reference(
    node: _Element,
    digest_method,  # noqa: ANN001
    id: str | None = None,
    uri: str | None = None,
    type: str | None = None,
) -> _Element:
    """Append a ``<Reference>`` under ``<SignedInfo>``.

    Mirrors ``xmlSecTmplSignatureAddReference``. ``node`` must be the
    ``<Signature>`` element; the reference is added under its first
    ``<SignedInfo>`` child.
    """
    _check_element(node)
    _check_transform(digest_method, 'digest_method')

    signed_info = _child_qname(node, _DSIG_NS, _NODE_SIGNED_INFO)
    if signed_info is None:
        raise _impl.Error('cannot add reference.')

    ref = _add_child(signed_info, _DSIG_NS, _NODE_REFERENCE)
    _set_optional(ref, 'Id', id)
    _set_optional(ref, 'URI', uri)
    _set_optional(ref, 'Type', type)

    digest = _add_child(ref, _DSIG_NS, _NODE_DIGEST_METHOD)
    digest.set('Algorithm', digest_method.href)
    _add_child(ref, _DSIG_NS, _NODE_DIGEST_VALUE)
    return ref


def add_transform(node: _Element, transform) -> _Element:  # noqa: ANN001
    """Add a ``<Transform>`` under ``<Reference>``'s ``<Transforms>``.

    Mirrors ``xmlSecTmplReferenceAddTransform``: creates ``<Transforms>``
    immediately before ``<DigestMethod>`` if not already present.
    """
    _check_element(node)
    _check_transform(transform)

    transforms = _child_qname(node, _DSIG_NS, _NODE_TRANSFORMS)
    if transforms is None:
        digest_method = _child_qname(node, _DSIG_NS, _NODE_DIGEST_METHOD)
        if digest_method is None:
            raise _impl.Error('cannot add transform.')
        transforms = _add_prev_sibling(digest_method, _DSIG_NS, _NODE_TRANSFORMS)

    t = _add_child(transforms, _DSIG_NS, _NODE_TRANSFORM)
    t.set('Algorithm', transform.href)
    return t


def ensure_key_info(node: _Element, id: str | None = None) -> _Element:
    """Ensure a ``<KeyInfo>`` exists under ``<Signature>``; return it.

    Mirrors ``xmlSecTmplSignatureEnsureKeyInfo``. ``node`` must be a
    ``<Signature>`` element.
    """
    _check_element(node)
    if node.tag != f'{{{_DSIG_NS}}}{_NODE_SIGNATURE}':
        raise _impl.Error('cannot ensure key info.')

    ki = _child_qname(node, _DSIG_NS, _NODE_KEY_INFO)
    if ki is None:
        ki = _add_child(node, _DSIG_NS, _NODE_KEY_INFO)
    if id is not None:
        ki.set('Id', id)
    return ki


def add_key_name(node: _Element, name: str | None = None) -> _Element:
    _check_element(node)
    kn = _add_child(node, _DSIG_NS, _NODE_KEY_NAME)
    if name is not None:
        kn.text = name
    return kn


def add_key_value(node: _Element) -> _Element:
    _check_element(node)
    return _add_child(node, _DSIG_NS, _NODE_KEY_VALUE)


def add_x509_data(node: _Element) -> _Element:
    _check_element(node)
    return _add_child(node, _DSIG_NS, _NODE_X509_DATA)


def x509_data_add_issuer_serial(node: _Element) -> _Element:
    _check_element(node)
    return _add_child(node, _DSIG_NS, _NODE_X509_ISSUER_SERIAL)


def x509_issuer_serial_add_issuer_name(node: _Element, name: str | None = None) -> _Element:
    _check_element(node)
    el = _add_child(node, _DSIG_NS, _NODE_X509_ISSUER_NAME)
    if name is not None:
        el.text = name
    return el


def x509_issuer_serial_add_serial_number(node: _Element, serial: str | None = None) -> _Element:
    _check_element(node)
    el = _add_child(node, _DSIG_NS, _NODE_X509_SERIAL_NUMBER)
    if serial is not None:
        el.text = serial
    return el


def x509_data_add_subject_name(node: _Element) -> _Element:
    _check_element(node)
    return _add_child(node, _DSIG_NS, _NODE_X509_SUBJECT_NAME)


def x509_data_add_ski(node: _Element) -> _Element:
    _check_element(node)
    return _add_child(node, _DSIG_NS, _NODE_X509_SKI)


def x509_data_add_certificate(node: _Element) -> _Element:
    _check_element(node)
    return _add_child(node, _DSIG_NS, _NODE_X509_CERTIFICATE)


def x509_data_add_crl(node: _Element) -> _Element:
    _check_element(node)
    return _add_child(node, _DSIG_NS, _NODE_X509_CRL)


def add_encrypted_key(
    node: _Element,
    method,  # noqa: ANN001
    id: str | None = None,
    type: str | None = None,
    recipient: str | None = None,
) -> _Element:
    """Add a ``<xenc:EncryptedKey>`` under ``<KeyInfo>``."""
    _check_element(node)
    _check_transform(method)

    # Create the EncryptedKey with an inlined xmlns="...xmlenc#" so it
    # matches libxmlsec's serialization (default-namespace declaration on
    # the element, no prefix).
    ek = _add_child(node, _ENC_NS, _NODE_ENCRYPTED_KEY, nsmap={None: _ENC_NS})
    _set_optional(ek, 'Id', id)
    _set_optional(ek, 'Type', type)
    _set_optional(ek, 'Recipient', recipient)

    em = _add_child(ek, _ENC_NS, _NODE_ENCRYPTION_METHOD)
    em.set('Algorithm', method.href)
    _add_child(ek, _ENC_NS, _NODE_CIPHER_DATA)
    return ek


def transform_add_c14n_inclusive_namespaces(node: _Element, prefixes: str | Sequence[str]) -> None:
    """Add ``<InclusiveNamespaces PrefixList="..."/>`` under a ``<Transform>``.

    Mirrors ``xmlSecTmplTransformAddC14NInclNamespaces``. ``prefixes`` may be
    a single string or a sequence of strings (joined with spaces).
    """
    _check_element(node)
    if isinstance(prefixes, str):
        prefix_list = prefixes
    elif isinstance(prefixes, (list, tuple)):
        prefix_list = ' '.join(prefixes)
    else:
        raise TypeError('expected instance of str or list of str')

    inc_ns = 'http://www.w3.org/2001/10/xml-exc-c14n#'
    el = _add_child(node, inc_ns, _NODE_INCLUSIVE_NAMESPACES, nsmap={None: inc_ns})
    el.set('PrefixList', prefix_list)


# ---------------------------------------------------------------------------
# XMLEnc template builders
# ---------------------------------------------------------------------------

def encrypted_data_create(
    node: _Element,
    method,  # noqa: ANN001
    id: str | None = None,
    type: str | None = None,
    mime_type: str | None = None,
    encoding: str | None = None,
    ns: str | None = None,
) -> _Element:
    """Create a detached ``<EncryptedData>`` template tree.

    Mirrors ``xmlSecTmplEncDataCreate``. The detached element is associated
    logically with ``node``'s document; the caller attaches it.
    """
    _check_element(node)
    _check_transform(method, 'method')

    if ns:
        nsmap = {ns: _ENC_NS}
    else:
        nsmap = {None: _ENC_NS}

    enc = etree.Element(QName(_ENC_NS, _NODE_ENCRYPTED_DATA), nsmap=nsmap)
    _set_optional(enc, 'Id', id)
    _set_optional(enc, 'Type', type)
    _set_optional(enc, 'MimeType', mime_type)
    _set_optional(enc, 'Encoding', encoding)

    em = _add_child(enc, _ENC_NS, _NODE_ENCRYPTION_METHOD)
    em.set('Algorithm', method.href)
    return enc


def encrypted_data_ensure_key_info(node: _Element, id: str | None = None, ns: str | None = None) -> _Element:
    """Ensure a ``<KeyInfo>`` (XMLDSig namespace) exists under ``<EncryptedData>``.

    Mirrors ``xmlSecTmplEncDataEnsureKeyInfo``: if ``<CipherData>`` is already
    present, the new ``<KeyInfo>`` is inserted immediately before it; otherwise
    it is appended. If a ``<KeyInfo>`` already exists and ``ns`` is given, the
    element is reconstructed with the requested namespace prefix (lxml's
    ``_Element`` namespace prefix is immutable, so we substitute the element
    rather than mutate it).
    """
    _check_element(node)
    ki = _child_qname(node, _DSIG_NS, _NODE_KEY_INFO)
    nsmap: dict | None = {ns: _DSIG_NS} if ns else {None: _DSIG_NS}
    if ki is None:
        cipher_data = _child_qname(node, _ENC_NS, _NODE_CIPHER_DATA)
        if cipher_data is None:
            ki = _add_child(node, _DSIG_NS, _NODE_KEY_INFO, nsmap=nsmap)
        else:
            idx = list(node).index(cipher_data)
            ki = node.makeelement(QName(_DSIG_NS, _NODE_KEY_INFO), {}, nsmap=nsmap)
            node.insert(idx, ki)
            # Mirror libxmlsec's xmlSecAddPrevSibling whitespace: a ``\n``
            # text node sits between the new element and ``cipher_data``.
            ki.tail = '\n'
    elif ns is not None and ki.prefix != ns:
        # Existing KeyInfo with a different (or absent) prefix; substitute.
        idx = list(node).index(ki)
        new_ki = node.makeelement(QName(_DSIG_NS, _NODE_KEY_INFO), {}, nsmap={ns: _DSIG_NS})
        new_ki.text = ki.text
        new_ki.tail = ki.tail
        for k, v in ki.attrib.items():
            new_ki.set(k, v)
        for child in list(ki):
            new_ki.append(child)
        node.remove(ki)
        node.insert(idx, new_ki)
        ki = new_ki
    if id is not None:
        ki.set('Id', id)
    return ki


def encrypted_data_ensure_cipher_value(node: _Element) -> _Element:
    """Ensure ``<CipherData><CipherValue/></CipherData>`` exists under ``<EncryptedData>``.

    Mirrors ``xmlSecTmplEncDataEnsureCipherValue``.
    """
    _check_element(node)
    cd = _child_qname(node, _ENC_NS, _NODE_CIPHER_DATA)
    if cd is None:
        cd = _add_child(node, _ENC_NS, _NODE_CIPHER_DATA)
    cv = _child_qname(cd, _ENC_NS, _NODE_CIPHER_VALUE)
    if cv is None:
        cv = _add_child(cd, _ENC_NS, _NODE_CIPHER_VALUE)
    return cv
