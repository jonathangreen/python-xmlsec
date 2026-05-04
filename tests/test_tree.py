from lxml import etree

import xmlsec
from tests import base
from xmlsec import _bridge

consts = xmlsec.constants


class TestTree(base.TestMemoryLeaks):
    def test_find_child(self):
        root = self.load_xml('sign_template.xml')
        si = xmlsec.tree.find_child(root, consts.NodeSignedInfo, consts.DSigNs)
        self.assertEqual(consts.NodeSignedInfo, si.tag.partition('}')[2])
        self.assertIsNone(xmlsec.tree.find_child(root, consts.NodeReference))
        self.assertIsNone(xmlsec.tree.find_child(root, consts.NodeSignedInfo, consts.EncNs))

    def test_find_child_bad_args(self):
        with self.assertRaises(TypeError):
            xmlsec.tree.find_child('', 0, True)

    def test_find_parent(self):
        root = self.load_xml('sign_template.xml')
        si = xmlsec.tree.find_child(root, consts.NodeSignedInfo, consts.DSigNs)
        self.assertIs(root, xmlsec.tree.find_parent(si, consts.NodeSignature))
        self.assertIsNone(xmlsec.tree.find_parent(root, consts.NodeSignedInfo))

    def test_find_parent_bad_args(self):
        with self.assertRaises(TypeError):
            xmlsec.tree.find_parent('', 0, True)

    def test_find_node(self):
        root = self.load_xml('sign_template.xml')
        ref = xmlsec.tree.find_node(root, consts.NodeReference)
        self.assertEqual(consts.NodeReference, ref.tag.partition('}')[2])
        self.assertIsNone(xmlsec.tree.find_node(root, consts.NodeReference, consts.EncNs))

    def test_find_node_bad_args(self):
        with self.assertRaises(TypeError):
            xmlsec.tree.find_node('', 0, True)

    def test_add_ids(self):
        root = self.load_xml('sign_template.xml')
        xmlsec.tree.add_ids(root, ['id1', 'id2', 'id3'])

    def test_structural_path_ignores_non_element_siblings(self):
        root = etree.fromstring(b'<root><!--comment--><?pi value?><target ID="target"/></root>')
        target = root[2]

        self.assertEqual([0], _bridge.structural_path(target))
        reparsed = _bridge.parse(etree.tostring(root.getroottree()))
        self.assertEqual('target', _bridge.locate(reparsed, [0]).tag)

    def test_add_ids_paths_ignore_non_element_siblings(self):
        xmlsec.tree.clear_ids()
        root = etree.fromstring(b'<root><!--comment--><?pi value?><target ID="target"/></root>')
        try:
            xmlsec.tree.add_ids(root, ['ID'])

            self.assertEqual([([0], 'ID', None)], _bridge.expand_tree_id_specs(root.getroottree()))
        finally:
            xmlsec.tree.clear_ids()

    def test_add_ids_bad_args(self):
        with self.assertRaises(TypeError):
            xmlsec.tree.add_ids('', [])
