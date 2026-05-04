import os
import tempfile

from lxml import etree

import xmlsec
from tests import base

consts = xmlsec.constants


class TestEncryptionContext(base.TestMemoryLeaks):
    def _create_aes_context(self):
        ctx = xmlsec.EncryptionContext()
        ctx.key = xmlsec.Key.generate(consts.KeyDataAes, 128, consts.KeyDataTypeSession)
        return ctx

    def _create_binary_template(self):
        root = etree.Element('root')
        enc_data = xmlsec.template.encrypted_data_create(
            root, consts.TransformAes128Cbc, type=consts.TypeEncContent, ns='xenc', mime_type='binary/octet-stream'
        )
        xmlsec.template.encrypted_data_ensure_cipher_value(enc_data)
        root.append(enc_data)
        return root, enc_data

    def test_init(self):
        ctx = xmlsec.EncryptionContext(manager=xmlsec.KeysManager())
        del ctx

    def test_init_no_keys_manager(self):
        ctx = xmlsec.EncryptionContext()
        del ctx

    def test_init_bad_args(self):
        with self.assertRaisesRegex(TypeError, 'KeysManager required'):
            xmlsec.EncryptionContext(manager='foo')

    def test_no_key(self):
        ctx = xmlsec.EncryptionContext(manager=xmlsec.KeysManager())
        self.assertIsNone(ctx.key)

    def test_get_key(self):
        ctx = xmlsec.EncryptionContext(manager=xmlsec.KeysManager())
        self.assertIsNone(ctx.key)
        ctx.key = xmlsec.Key.from_file(self.path('rsacert.pem'), format=consts.KeyDataFormatCertPem)
        self.assertIsNotNone(ctx.key)

    def test_del_key(self):
        ctx = xmlsec.EncryptionContext(manager=xmlsec.KeysManager())
        ctx.key = xmlsec.Key.from_file(self.path('rsacert.pem'), format=consts.KeyDataFormatCertPem)
        del ctx.key
        self.assertIsNone(ctx.key)

    def test_set_key(self):
        ctx = xmlsec.EncryptionContext(manager=xmlsec.KeysManager())
        ctx.key = xmlsec.Key.from_file(self.path('rsacert.pem'), format=consts.KeyDataFormatCertPem)
        self.assertIsNotNone(ctx.key)

    def test_set_key_bad_type(self):
        ctx = xmlsec.EncryptionContext(manager=xmlsec.KeysManager())
        with self.assertRaisesRegex(TypeError, r'instance of \*xmlsec.Key\* expected.'):
            ctx.key = ''

    def test_set_invalid_key(self):
        ctx = xmlsec.EncryptionContext(manager=xmlsec.KeysManager())
        with self.assertRaisesRegex(TypeError, 'empty key.'):
            ctx.key = xmlsec.Key()

    def test_encrypt_xml(self):
        root = self.load_xml('enc1-in.xml')
        enc_data = xmlsec.template.encrypted_data_create(root, consts.TransformAes128Cbc, type=consts.TypeEncElement, ns='xenc')
        xmlsec.template.encrypted_data_ensure_cipher_value(enc_data)
        ki = xmlsec.template.encrypted_data_ensure_key_info(enc_data, ns='dsig')
        ek = xmlsec.template.add_encrypted_key(ki, consts.TransformRsaOaep)
        xmlsec.template.encrypted_data_ensure_cipher_value(ek)
        data = root.find('./Data')
        self.assertIsNotNone(data)

        manager = xmlsec.KeysManager()
        manager.add_key(xmlsec.Key.from_file(self.path('rsacert.pem'), format=consts.KeyDataFormatCertPem))

        ctx = xmlsec.EncryptionContext(manager)
        ctx.key = xmlsec.Key.generate(consts.KeyDataAes, 128, consts.KeyDataTypeSession)

        encrypted = ctx.encrypt_xml(enc_data, data)
        self.assertIsNotNone(encrypted)

        enc_method = xmlsec.tree.find_child(enc_data, consts.NodeEncryptionMethod, consts.EncNs)
        self.assertIsNotNone(enc_method)
        self.assertEqual('http://www.w3.org/2001/04/xmlenc#aes128-cbc', enc_method.get('Algorithm'))
        ki = xmlsec.tree.find_child(enc_data, consts.NodeKeyInfo, consts.DSigNs)
        self.assertIsNotNone(ki)
        enc_method2 = xmlsec.tree.find_node(ki, consts.NodeEncryptionMethod, consts.EncNs)
        self.assertIsNotNone(enc_method2)
        self.assertEqual('http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p', enc_method2.get('Algorithm'))
        cipher_value = xmlsec.tree.find_node(ki, consts.NodeCipherValue, consts.EncNs)
        self.assertIsNotNone(cipher_value)

    def test_encrypt_xml_attached_template_updates_full_document(self):
        root = etree.Element('Envelope')
        data = etree.SubElement(root, 'Data')
        data.text = 'secret'
        template_holder = etree.SubElement(root, 'Templates')
        enc_data = xmlsec.template.encrypted_data_create(root, consts.TransformAes128Cbc, type=consts.TypeEncElement, ns='xenc')
        xmlsec.template.encrypted_data_ensure_cipher_value(enc_data)
        template_holder.append(enc_data)

        encrypted = self._create_aes_context().encrypt_xml(enc_data, data)

        self.assertIs(root[0], encrypted)
        self.assertEqual(f'{{{consts.EncNs}}}{consts.NodeEncryptedData}', encrypted.tag)
        self.assertEqual(0, len(root.find('Templates')))

    def test_encrypt_xml_bad_args(self):
        ctx = xmlsec.EncryptionContext()
        with self.assertRaises(TypeError):
            ctx.encrypt_xml('', 0)

    def test_encrypt_xml_bad_template(self):
        ctx = xmlsec.EncryptionContext()
        with self.assertRaisesRegex(xmlsec.Error, 'unsupported `Type`, it should be `element`'):
            ctx.encrypt_xml(etree.Element('root'), etree.Element('node'))

    def test_encrypt_xml_bad_template_bad_type_attribute(self):
        ctx = xmlsec.EncryptionContext()
        with self.assertRaisesRegex(xmlsec.Error, 'unsupported `Type`, it should be `element`'):
            root = etree.Element('root')
            root.attrib['Type'] = 'foo'
            ctx.encrypt_xml(root, etree.Element('node'))

    def test_encrypt_xml_fail(self):
        ctx = xmlsec.EncryptionContext()
        with self.assertRaisesRegex(xmlsec.Error, 'failed to encrypt xml'):
            root = etree.Element('root')
            root.attrib['Type'] = consts.TypeEncElement
            ctx.encrypt_xml(root, etree.Element('node'))

    def test_encrypt_binary(self):
        root = self.load_xml('enc2-in.xml')
        enc_data = xmlsec.template.encrypted_data_create(
            root, consts.TransformAes128Cbc, type=consts.TypeEncContent, ns='xenc', mime_type='binary/octet-stream'
        )
        xmlsec.template.encrypted_data_ensure_cipher_value(enc_data)
        ki = xmlsec.template.encrypted_data_ensure_key_info(enc_data, ns='dsig')
        ek = xmlsec.template.add_encrypted_key(ki, consts.TransformRsaOaep)
        xmlsec.template.encrypted_data_ensure_cipher_value(ek)

        manager = xmlsec.KeysManager()
        manager.add_key(xmlsec.Key.from_file(self.path('rsacert.pem'), format=consts.KeyDataFormatCertPem))

        ctx = xmlsec.EncryptionContext(manager)
        ctx.key = xmlsec.Key.generate(consts.KeyDataAes, 128, consts.KeyDataTypeSession)

        encrypted = ctx.encrypt_binary(enc_data, b'test')
        self.assertIsNotNone(encrypted)
        self.assertEqual(f'{{{consts.EncNs}}}{consts.NodeEncryptedData}', encrypted.tag)

        enc_method = xmlsec.tree.find_child(enc_data, consts.NodeEncryptionMethod, consts.EncNs)
        self.assertIsNotNone(enc_method)
        self.assertEqual('http://www.w3.org/2001/04/xmlenc#aes128-cbc', enc_method.get('Algorithm'))

        ki = xmlsec.tree.find_child(enc_data, consts.NodeKeyInfo, consts.DSigNs)
        self.assertIsNotNone(ki)
        enc_method2 = xmlsec.tree.find_node(ki, consts.NodeEncryptionMethod, consts.EncNs)
        self.assertIsNotNone(enc_method2)
        self.assertEqual('http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p', enc_method2.get('Algorithm'))
        cipher_value = xmlsec.tree.find_node(ki, consts.NodeCipherValue, consts.EncNs)
        self.assertIsNotNone(cipher_value)

    def test_encrypt_binary_preserves_attached_template_tail(self):
        _root, enc_data = self._create_binary_template()
        enc_data.tail = 'tail-text'

        encrypted = self._create_aes_context().encrypt_binary(enc_data, b'test')

        self.assertEqual(f'{{{consts.EncNs}}}{consts.NodeEncryptedData}', encrypted.tag)
        self.assertEqual('tail-text', encrypted.tail)

    def test_encrypt_binary_bad_args(self):
        ctx = xmlsec.EncryptionContext()
        with self.assertRaises(TypeError):
            ctx.encrypt_binary('', 0)

    def test_encrypt_binary_bad_template(self):
        ctx = xmlsec.EncryptionContext()
        with self.assertRaisesRegex(xmlsec.Error, 'failed to encrypt binary'):
            ctx.encrypt_binary(etree.Element('root'), b'data')

    def test_encrypt_uri(self):
        root = self.load_xml('enc2-in.xml')
        enc_data = xmlsec.template.encrypted_data_create(
            root, consts.TransformAes128Cbc, type=consts.TypeEncContent, ns='xenc', mime_type='binary/octet-stream'
        )
        xmlsec.template.encrypted_data_ensure_cipher_value(enc_data)
        ki = xmlsec.template.encrypted_data_ensure_key_info(enc_data, ns='dsig')
        ek = xmlsec.template.add_encrypted_key(ki, consts.TransformRsaOaep)
        xmlsec.template.encrypted_data_ensure_cipher_value(ek)

        manager = xmlsec.KeysManager()
        manager.add_key(xmlsec.Key.from_file(self.path('rsacert.pem'), format=consts.KeyDataFormatCertPem))

        ctx = xmlsec.EncryptionContext(manager)
        ctx.key = xmlsec.Key.generate(consts.KeyDataAes, 128, consts.KeyDataTypeSession)

        with tempfile.NamedTemporaryFile(delete=False) as tmpfile:
            tmpfile.write(b'test')

        encrypted = ctx.encrypt_binary(enc_data, 'file://' + tmpfile.name)
        self.assertIsNotNone(encrypted)
        self.assertEqual(f'{{{consts.EncNs}}}{consts.NodeEncryptedData}', encrypted.tag)

        enc_method = xmlsec.tree.find_child(enc_data, consts.NodeEncryptionMethod, consts.EncNs)
        self.assertIsNotNone(enc_method)
        self.assertEqual('http://www.w3.org/2001/04/xmlenc#aes128-cbc', enc_method.get('Algorithm'))

        ki = xmlsec.tree.find_child(enc_data, consts.NodeKeyInfo, consts.DSigNs)
        self.assertIsNotNone(ki)
        enc_method2 = xmlsec.tree.find_node(ki, consts.NodeEncryptionMethod, consts.EncNs)
        self.assertIsNotNone(enc_method2)
        self.assertEqual('http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p', enc_method2.get('Algorithm'))
        cipher_value = xmlsec.tree.find_node(ki, consts.NodeCipherValue, consts.EncNs)
        self.assertIsNotNone(cipher_value)

    def test_encrypt_uri_preserves_attached_template_tail(self):
        _root, enc_data = self._create_binary_template()
        enc_data.tail = 'tail-text'
        with tempfile.NamedTemporaryFile(delete=False) as tmpfile:
            tmpfile.write(b'test')
            tmpfile_name = tmpfile.name

        try:
            encrypted = self._create_aes_context().encrypt_uri(enc_data, 'file://' + tmpfile_name)
        finally:
            os.unlink(tmpfile_name)

        self.assertEqual(f'{{{consts.EncNs}}}{consts.NodeEncryptedData}', encrypted.tag)
        self.assertEqual('tail-text', encrypted.tail)

    def test_encrypt_uri_bad_args(self):
        ctx = xmlsec.EncryptionContext()
        with self.assertRaises(TypeError):
            ctx.encrypt_uri('', 0)

    def test_encrypt_uri_fail(self):
        ctx = xmlsec.EncryptionContext()
        with self.assertRaisesRegex(xmlsec.Error, 'failed to encrypt URI'):
            ctx.encrypt_uri(etree.Element('root'), '')

    def test_decrypt1(self):
        self.check_decrypt(1)

    def test_decrypt2(self):
        self.check_decrypt(2)

    def test_decrypt_key(self):
        root = self.load_xml('enc3-out.xml')
        enc_key = xmlsec.tree.find_child(root, consts.NodeEncryptedKey, consts.EncNs)
        self.assertIsNotNone(enc_key)

        manager = xmlsec.KeysManager()
        manager.add_key(xmlsec.Key.from_file(self.path('rsakey.pem'), format=consts.KeyDataFormatPem))
        ctx = xmlsec.EncryptionContext(manager)
        keydata = ctx.decrypt(enc_key)
        ctx.reset()
        root.remove(enc_key)
        ctx.key = xmlsec.Key.from_binary_data(consts.KeyDataAes, keydata)
        enc_data = xmlsec.tree.find_child(root, consts.NodeEncryptedData, consts.EncNs)
        self.assertIsNotNone(enc_data)
        decrypted = ctx.decrypt(enc_data)
        self.assertIsNotNone(decrypted)
        self.assertEqual(self.load_xml('enc3-in.xml'), decrypted)

    def test_decrypt_uses_tree_add_ids_for_retrieval_method(self):
        root = self.load_xml('enc2-out.xml')
        enc_data = xmlsec.tree.find_child(root, consts.NodeEncryptedData, consts.EncNs)
        self.assertIsNotNone(enc_data)
        key_info = xmlsec.tree.find_child(enc_data, consts.NodeKeyInfo, consts.DSigNs)
        self.assertIsNotNone(key_info)
        enc_key = xmlsec.tree.find_child(key_info, consts.NodeEncryptedKey, consts.EncNs)
        self.assertIsNotNone(enc_key)
        enc_key.set('Id', 'key')
        key_info.remove(enc_key)
        root.insert(0, enc_key)
        retrieval = etree.Element(etree.QName(consts.DSigNs, 'RetrievalMethod'), nsmap={'dsig': consts.DSigNs})
        retrieval.set('URI', '#key')
        retrieval.set('Type', consts.EncNs + consts.NodeEncryptedKey)
        key_info.append(retrieval)
        xmlsec.tree.add_ids(root, ['Id'])

        try:
            manager = xmlsec.KeysManager()
            manager.add_key(xmlsec.Key.from_file(self.path('rsakey.pem'), format=consts.KeyDataFormatPem))
            ctx = xmlsec.EncryptionContext(manager)
            decrypted = ctx.decrypt(enc_data)
        finally:
            xmlsec.tree.clear_ids()

        self.assertIs(root, decrypted)
        self.assertIsNone(xmlsec.tree.find_child(root, consts.NodeEncryptedData, consts.EncNs))
        self.assertIn('test', ''.join(root.itertext()))

    def check_decrypt(self, i):
        root = self.load_xml(f'enc{i}-out.xml')
        enc_data = xmlsec.tree.find_child(root, consts.NodeEncryptedData, consts.EncNs)
        self.assertIsNotNone(enc_data)

        manager = xmlsec.KeysManager()
        manager.add_key(xmlsec.Key.from_file(self.path('rsakey.pem'), format=consts.KeyDataFormatPem))
        ctx = xmlsec.EncryptionContext(manager)
        decrypted = ctx.decrypt(enc_data)
        self.assertIsNotNone(decrypted)
        self.assertEqual(self.load_xml(f'enc{i}-in.xml'), root)

    def test_decrypt_bad_args(self):
        ctx = xmlsec.EncryptionContext()
        with self.assertRaises(TypeError):
            ctx.decrypt('')
