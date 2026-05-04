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

    Each index points into the parent's element-only children; comments,
    processing instructions, and text nodes are ignored to match the C
    resolver. An empty list means ``elem`` is the document root. The path
    round-trips faithfully across serialize + parse on both lxml and
    python-xmlsec's libxml2.
    """
    path: List[int] = []
    cur = elem
    while True:
        parent = cur.getparent()
        if parent is None:
            break
        path.insert(0, _element_children(parent).index(cur))
        cur = parent
    return path


def locate(tree: _ElementTree, path: List[int]) -> _Element:
    """Inverse of ``structural_path``."""
    cur = tree.getroot()
    for idx in path:
        cur = _element_children(cur)[idx]
    return cur


def _element_children(elem: _Element) -> List[_Element]:
    return [child for child in elem if isinstance(child.tag, str)]


# Process-level registry populated by ``tree.add_ids``. Each entry is a
# ``(subtree_root, list_of_attr_names)`` pair. Expanded just-in-time at
# every crypto call into per-element id specs against the freshly parsed
# doc inside the C extension.
#
# Strong refs are unavoidable here: lxml's ``_Element`` proxies, the
# ``_ElementTree`` wrapper, and ``DocInfo`` are all NOT weakref-able
# (verified empirically), so we cannot let GC drop registrations
# automatically when the user's tree becomes unreachable. To keep this
# from accumulating forever in long-running processes:
#
#  - ``expand_tree_id_specs`` prunes any entry whose root has been
#    detached from its tree (``getroottree()`` raises or returns a
#    different root than the one originally registered against). This
#    catches the case where the user explicitly removes the registered
#    subtree from its document.
#
#  - ``clear_id_registrations`` is exposed publicly via
#    ``xmlsec.tree.clear_ids`` so applications running batch / per-
#    request workloads can drop everything between requests.
#
# Without an explicit ``clear_ids`` call, registrations created with
# ``tree.add_ids(some_root, [...])`` keep ``some_root`` (and therefore
# the entire document tree it belongs to) alive in this list until the
# user detaches the registered subtree from the document. For short
# scripts that's fine. For long-lived services, prefer
# ``SignatureContext.register_id`` (which is per-context and goes away
# with the context) or call ``xmlsec.tree.clear_ids`` between requests.
_TREE_ID_REGISTRATIONS: List[Tuple[_Element, List[str]]] = []


def add_id_registration(root: _Element, attr_names: List[str]) -> None:
    _TREE_ID_REGISTRATIONS.append((root, list(attr_names)))


def clear_id_registrations() -> None:
    """Drop every entry in the process-level ``tree.add_ids`` registry."""
    _TREE_ID_REGISTRATIONS.clear()


def _is_live_root(elem: _Element) -> bool:
    """True if ``elem`` is still attached to (or is) a document root.

    A registration whose root element is no longer reachable through any
    document tree is dead — it cannot contribute id specs anymore. lxml
    raises if ``getroottree()`` is called on a fully-destroyed proxy; we
    treat any failure as dead.
    """
    try:
        return elem.getroottree().getroot() is not None
    except Exception:  # noqa: BLE001
        return False


def expand_tree_id_specs(op_tree: _ElementTree) -> List[IdSpec]:
    """Resolve any ``tree.add_ids`` registrations against ``op_tree``.

    Walks each registered subtree once and emits one (path, attr_name, None)
    spec per descendant whose attribute is present. Tree identity is checked
    by comparing root elements (lxml returns a fresh ``_ElementTree`` proxy
    on every ``getroottree()``, so ``is`` on the wrapper would always fail).
    Prunes dead registrations from ``_TREE_ID_REGISTRATIONS`` as a side
    effect to bound long-running-process memory.
    """
    op_root = op_tree.getroot()
    specs: List[IdSpec] = []
    # Iterate over a snapshot so concurrent add_id_registration calls
    # are not visible to this expansion (and survive pruning below).
    snapshot = list(_TREE_ID_REGISTRATIONS)
    survivors: List[Tuple[_Element, List[str]]] = []
    for root, attr_names in snapshot:
        if not _is_live_root(root):
            continue  # dead — drop
        survivors.append((root, attr_names))
        if root.getroottree().getroot() is not op_root:
            continue  # alive but not relevant to this op
        for descendant in root.iter():
            for attr_name in attr_names:
                if descendant.get(attr_name) is not None:
                    specs.append((structural_path(descendant), attr_name, None))
    # Prune in place. Any entries appended by another thread during this
    # expansion sit beyond ``len(snapshot)`` in the live list and are
    # preserved by replacing only the snapshot prefix.
    _TREE_ID_REGISTRATIONS[: len(snapshot)] = survivors
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


def replace_in_place_preserving_path(target: _Element, source: _Element, preserve_path: List[int]) -> _Element:
    """Mutate ``target`` to match ``source`` while preserving one descendant.

    ``preserve_path`` uses the same element-only structural indexes as
    ``structural_path``. The element at that path in ``target`` keeps its
    Python identity, but its contents are updated from the corresponding
    ``source`` element. All other descendants are replaced from ``source``.
    """
    if not preserve_path:
        replace_in_place(target, source)
        return target

    preserve_idx = preserve_path[0]
    target_child = _element_children(target)[preserve_idx]
    source_child = _element_children(source)[preserve_idx]
    preserved = replace_in_place_preserving_path(target_child, source_child, preserve_path[1:])

    target.text = source.text
    target.tail = source.tail
    target.attrib.clear()
    for k, v in source.attrib.items():
        target.set(k, v)
    for child in list(target):
        target.remove(child)
    for child in list(source):
        if child is source_child:
            target.append(target_child)
        else:
            target.append(copy.deepcopy(child))
    return preserved
