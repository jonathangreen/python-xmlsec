"""Bytes/structural-path bridge between lxml and the C extension.

The C extension (``xmlsec._impl``) accepts XML as bytes and structural
index paths and returns XML as bytes. This module owns the lxml side:
serializing the user's tree, computing structural paths, parsing the
result, and splicing the post-op subtree back onto the user's lxml
``_Element`` so its identity is preserved.

No xmlNodePtr ever crosses between lxml's libxml2 and python-xmlsec's
libxml2 — that's the whole point of #356.
"""

from __future__ import annotations

import copy
from typing import List, Tuple

from lxml import etree
from lxml.etree import _Element, _ElementTree

# An id spec is (structural_path, attr_name, attr_namespace_or_None).
# Resolved just-in-time before each crypto call.
IdSpec = Tuple[List[int], str, str | None]


def serialize(elem: _Element) -> Tuple[bytes, str | None]:
    """Serialize the document containing ``elem`` to XML bytes.

    Always serializes the *full* document (``elem.getroottree()``) so
    document-level comments, processing instructions, DOCTYPE/internal
    subset, and entity declarations survive the round-trip. The base URL
    is captured from ``tree.docinfo.URL`` so relative references can be
    re-resolved on the C side (``xmlReadMemory`` honors it).
    """
    tree = elem.getroottree()
    base_url = tree.docinfo.URL if tree.docinfo is not None else None
    data = etree.tostring(tree, xml_declaration=True, encoding='UTF-8')
    return data, base_url


def parse(data: bytes, base_url: str | None = None) -> _ElementTree:
    """Parse XML bytes into an lxml ElementTree using lxml's own libxml2.

    Mirrors the parser flags python-xmlsec's C side uses: no network,
    no entity expansion of external entities, no whitespace stripping
    (``remove_blank_text=False``).
    """
    parser = etree.XMLParser(resolve_entities=False, no_network=True, remove_blank_text=False)
    return etree.ElementTree(etree.fromstring(data, parser=parser, base_url=base_url))


def structural_path(elem: _Element) -> List[int]:
    """Return the path from the document root to ``elem`` as a list of indexes.

    Each index points into the parent's element-only children (lxml's
    ``list(parent)`` semantics). An empty list means ``elem`` is the
    document root. The path round-trips faithfully across serialize +
    parse on both lxml and python-xmlsec's libxml2.
    """
    path: List[int] = []
    cur = elem
    while True:
        parent = cur.getparent()
        if parent is None:
            break
        path.insert(0, list(parent).index(cur))
        cur = parent
    return path


def locate(tree: _ElementTree, path: List[int]) -> _Element:
    """Inverse of ``structural_path``."""
    cur = tree.getroot()
    for idx in path:
        cur = list(cur)[idx]
    return cur


# Process-level registry populated by ``tree.add_ids``. Each entry is a
# ``(subtree_root, list_of_attr_names)`` pair. Expanded just-in-time at
# every crypto call into per-element id specs against the freshly
# parsed doc inside the C extension. Strong refs are used for now;
# PR 6 will move to a registry keyed on the user's _ElementTree once
# ``tree.add_ids`` is fully migrated to Python.
_TREE_ID_REGISTRATIONS: List[Tuple[_Element, List[str]]] = []


def add_id_registration(root: _Element, attr_names: List[str]) -> None:
    _TREE_ID_REGISTRATIONS.append((root, list(attr_names)))


def expand_tree_id_specs(op_tree: _ElementTree) -> List[IdSpec]:
    """Resolve any ``tree.add_ids`` registrations against ``op_tree``.

    Walks each registered subtree once and emits one (path, attr_name, None)
    spec per descendant whose attribute is present. Tree identity is checked
    by comparing root elements (lxml returns a fresh ``_ElementTree`` proxy
    on every ``getroottree()``, so ``is`` on the wrapper would always fail).
    Dead registrations are skipped but not pruned here.
    """
    op_root = op_tree.getroot()
    specs: List[IdSpec] = []
    for root, attr_names in _TREE_ID_REGISTRATIONS:
        try:
            reg_root = root.getroottree().getroot()
        except Exception:  # noqa: BLE001 — element invalidated
            continue
        if reg_root is not op_root:
            continue
        for descendant in root.iter():
            for attr_name in attr_names:
                if descendant.get(attr_name) is not None:
                    specs.append((structural_path(descendant), attr_name, None))
    return specs


def replace_in_place(target: _Element, source: _Element) -> None:
    """Mutate ``target`` so its children/text/attribs match ``source``.

    Tag, prefix, and nsmap of ``target`` are not touched — lxml's
    ``_Element`` does not allow mutating those, and every wrapped op
    leaves the addressed element's identity intact (sign mutates only
    children of ``<Signature>``; encrypt/decrypt that fully replace an
    element route through ``parent.replace`` instead).
    """
    target.text = source.text
    target.tail = source.tail
    target.attrib.clear()
    for k, v in source.attrib.items():
        target.set(k, v)
    for child in list(target):
        target.remove(child)
    for child in list(source):
        target.append(copy.deepcopy(child))
