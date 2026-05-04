"""Pure-Python implementation of ``xmlsec.tree``.

These helpers used to wrap libxmlsec's ``xmlSecFindChild`` /
``xmlSecFindParent`` / ``xmlSecFindNode`` and mutate libxml2 directly. They
were on the lxml/xmlsec1 ABI boundary even though they did no cryptography.
The pure-Python implementations below keep the exact same behavior using
lxml's own libxml2, so xmlsec1 never sees an lxml node here.

``add_ids`` still calls into the C extension for now — it touches the libxml2
ID table and is migrated in a later PR.
"""

from __future__ import annotations

import itertools
from typing import Iterable

from lxml import etree
from lxml.etree import _Element

from xmlsec import _impl

_consts = _impl.constants
add_ids = _impl.tree.add_ids  # re-export the C implementation unchanged

__all__ = ['add_ids', 'find_child', 'find_node', 'find_parent']


def _qname(name: str, namespace: str) -> str:
    """Build the Clark-notation tag string libxmlsec compares against.

    libxmlsec's ``xmlSecCheckNodeName`` matches when the element's local name
    and namespace href both match. lxml encodes the same information in
    ``_Element.tag`` as ``"{href}localname"`` (or just ``"localname"`` for
    no-namespace elements).
    """
    if namespace:
        return f'{{{namespace}}}{name}'
    return name


def _check_args(node: _Element, name: str, namespace: str) -> None:
    if not etree.iselement(node):
        raise TypeError('expected lxml.etree._Element')
    if not isinstance(name, str):
        raise TypeError('name must be a string')
    if not isinstance(namespace, str):
        raise TypeError('namespace must be a string')


def find_child(parent: _Element, name: str, namespace: str = _consts.DSigNs) -> _Element | None:
    """Return the first direct child of ``parent`` matching ``name``/``namespace``.

    Matches ``xmlSecFindChild`` semantics: only direct element children are
    scanned, in document order; the first match is returned. The default
    namespace mirrors libxmlsec's default of the XMLDSig namespace.
    """
    _check_args(parent, name, namespace)
    target = _qname(name, namespace)
    for child in parent:
        if child.tag == target:
            return child
    return None


def find_parent(node: _Element, name: str, namespace: str = _consts.DSigNs) -> _Element | None:
    """Walk the ancestor axis of ``node`` (inclusive of ``node``) and return the first match.

    Matches ``xmlSecFindParent`` semantics: ``node`` itself is checked first,
    then each ancestor toward the document root. Returns None if no match.
    """
    _check_args(node, name, namespace)
    target = _qname(name, namespace)
    for cur in itertools.chain([node], node.iterancestors()):
        if cur.tag == target:
            return cur
    return None


def find_node(node: _Element, name: str, namespace: str = _consts.DSigNs) -> _Element | None:
    """Find the first descendant of ``node`` (or ``node`` itself) matching ``name``/``namespace``.

    Matches ``xmlSecFindNode`` semantics: depth-first scan starting at
    ``node``, then continuing across ``node``'s element-level following
    siblings (and their descendants), in document order. The vast majority
    of callers pass the document root, where the sibling-scan is a no-op.
    """
    _check_args(node, name, namespace)
    target = _qname(name, namespace)
    candidates: Iterable[_Element] = itertools.chain([node], node.itersiblings())
    for start in candidates:
        for hit in start.iter(target):
            return hit
    return None
