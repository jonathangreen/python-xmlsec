// Copyright (c) 2017 Ryan Leckey
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

#include "common.h"
#include "platform.h"
#include "exception.h"
#include "constants.h"
#include "keys.h"
#include "bridge.h"
#include "lxml.h"

#include <xmlsec/xmlenc.h>
#include <xmlsec/xmltree.h>
#include <libxml/tree.h>

// Backwards compatibility with xmlsec 1.2
#ifndef XMLSEC_KEYINFO_FLAGS_LAX_KEY_SEARCH
#define XMLSEC_KEYINFO_FLAGS_LAX_KEY_SEARCH 0x00008000
#endif

typedef struct {
    PyObject_HEAD
    xmlSecEncCtxPtr handle;
    PyXmlSec_KeysManager* manager;
} PyXmlSec_EncryptionContext;

static PyObject* PyXmlSec_EncryptionContext__new__(PyTypeObject *type, PyObject *args, PyObject *kwargs) {
    PyXmlSec_EncryptionContext* ctx = (PyXmlSec_EncryptionContext*)PyType_GenericNew(type, args, kwargs);
    PYXMLSEC_DEBUGF("%p: new enc context", ctx);
    if (ctx != NULL) {
        ctx->handle = NULL;
        ctx->manager = NULL;
    }
    return (PyObject*)(ctx);
}

static int PyXmlSec_EncryptionContext__init__(PyObject* self, PyObject* args, PyObject* kwargs) {
    static char *kwlist[] = { "manager", NULL};

    PyXmlSec_KeysManager* manager = NULL;
    PyXmlSec_EncryptionContext* ctx = (PyXmlSec_EncryptionContext*)self;

    PYXMLSEC_DEBUGF("%p: init enc context", self);
    if (!PyArg_ParseTupleAndKeywords(args, kwargs, "|O&:__init__", kwlist, PyXmlSec_KeysManagerConvert, &manager)) {
        goto ON_FAIL;
    }
    ctx->handle = xmlSecEncCtxCreate(manager != NULL ? manager->handle : NULL);
    if (ctx->handle == NULL) {
        PyXmlSec_SetLastError("failed to create the encryption context");
        goto ON_FAIL;
    }
    ctx->manager = manager;
    PYXMLSEC_DEBUGF("%p: init enc context - ok, manager - %p", self, manager);

    // xmlsec 1.3 changed the key search to strict mode, causing various examples
    // in the docs to fail. For backwards compatibility, this changes it back to
    // lax mode for now.
    ctx->handle->keyInfoReadCtx.flags = XMLSEC_KEYINFO_FLAGS_LAX_KEY_SEARCH;
    ctx->handle->keyInfoWriteCtx.flags = XMLSEC_KEYINFO_FLAGS_LAX_KEY_SEARCH;

    return 0;
ON_FAIL:
    PYXMLSEC_DEBUGF("%p: init enc context - failed", self);
    Py_XDECREF(manager);
    return -1;
}

static void PyXmlSec_EncryptionContext__del__(PyObject* self) {
    PyXmlSec_EncryptionContext* ctx = (PyXmlSec_EncryptionContext*)self;

    PYXMLSEC_DEBUGF("%p: delete enc context", self);

    if (ctx->handle != NULL) {
        xmlSecEncCtxDestroy(ctx->handle);
    }
    // release manager object
    Py_XDECREF(ctx->manager);
    Py_TYPE(self)->tp_free(self);
}

static const char PyXmlSec_EncryptionContextKey__doc__[] = "Encryption key.\n";
static PyObject* PyXmlSec_EncryptionContextKeyGet(PyObject* self, void* closure) {
    PyXmlSec_EncryptionContext* ctx = ((PyXmlSec_EncryptionContext*)self);
    PyXmlSec_Key* key;

    if (ctx->handle->encKey == NULL) {
        Py_RETURN_NONE;
    }

    key = PyXmlSec_NewKey();
    key->handle = ctx->handle->encKey;
    key->is_own = 0;
    return (PyObject*)key;
}

static int PyXmlSec_EncryptionContextKeySet(PyObject* self, PyObject* value, void* closure) {
    PyXmlSec_EncryptionContext* ctx = (PyXmlSec_EncryptionContext*)self;
    PyXmlSec_Key* key;

    PYXMLSEC_DEBUGF("%p, %p", self, value);

    if (value == NULL) {  // key deletion
        if (ctx->handle->encKey != NULL) {
            xmlSecKeyDestroy(ctx->handle->encKey);
            ctx->handle->encKey = NULL;
        }
        return 0;
    }

    if (!PyObject_IsInstance(value, (PyObject*)PyXmlSec_KeyType)) {
        PyErr_SetString(PyExc_TypeError, "instance of *xmlsec.Key* expected.");
        return -1;
    }

    key = (PyXmlSec_Key*)value;
    if (key->handle == NULL) {
        PyErr_SetString(PyExc_TypeError, "empty key.");
        return -1;
    }

    if (ctx->handle->encKey != NULL) {
        xmlSecKeyDestroy(ctx->handle->encKey);
    }

    ctx->handle->encKey = xmlSecKeyDuplicate(key->handle);
    if (ctx->handle->encKey == NULL) {
        PyXmlSec_SetLastError("failed to duplicate key");
        return -1;
    }
    return 0;
}

static const char PyXmlSec_EncryptionContextReset__doc__[] = \
    "reset() -> None\n"\
    "Reset this context, user settings are not touched.\n";
static PyObject* PyXmlSec_EncryptionContextReset(PyObject* self, PyObject* args, PyObject* kwargs) {
    PyXmlSec_EncryptionContext* ctx = (PyXmlSec_EncryptionContext*)self;

    PYXMLSEC_DEBUGF("%p: reset context - start", self);
    Py_BEGIN_ALLOW_THREADS;
    xmlSecEncCtxReset(ctx->handle);
    PYXMLSEC_DUMP(xmlSecEncCtxDebugDump, ctx->handle);
    Py_END_ALLOW_THREADS;
    PYXMLSEC_DEBUGF("%p: reset context - ok", self);
    Py_RETURN_NONE;
}

// _encrypt_binary(template_bytes, data) -> bytes
//
// Round-trips a single template fragment: parse, run
// xmlSecEncCtxBinaryEncrypt on its root, serialize back.
static const char PyXmlSec_EncryptionContext_EncryptBinary__doc__[] = \
    "_encrypt_binary(template_bytes, data) -> bytes\n"
    "Internal: encrypt binary data into a fragment-shaped EncryptedData template.\n";
static PyObject* PyXmlSec_EncryptionContext_EncryptBinary(PyObject* self, PyObject* args, PyObject* kwargs) {
    static char *kwlist[] = { "template_bytes", "data", NULL };
    PyXmlSec_EncryptionContext* ctx = (PyXmlSec_EncryptionContext*)self;
    const char* tmpl = NULL;
    Py_ssize_t tmpl_len = 0;
    const char* data = NULL;
    Py_ssize_t data_size = 0;
    xmlDocPtr doc = NULL;
    xmlNodePtr template_root;
    PyObject* result = NULL;
    int rv;

    if (!PyArg_ParseTupleAndKeywords(args, kwargs, "y#y#:_encrypt_binary", kwlist,
        &tmpl, &tmpl_len, &data, &data_size))
    {
        goto ON_FAIL;
    }

    doc = pyxmlsec_load_doc(tmpl, tmpl_len, NULL);
    if (doc == NULL) goto ON_FAIL;
    template_root = xmlDocGetRootElement(doc);
    if (template_root == NULL) {
        PyErr_SetString(PyXmlSec_Error, "template fragment has no root element");
        goto ON_FAIL;
    }

    Py_BEGIN_ALLOW_THREADS;
    rv = xmlSecEncCtxBinaryEncrypt(ctx->handle, template_root, (const xmlSecByte*)data, (xmlSecSize)data_size);
    PYXMLSEC_DUMP(xmlSecEncCtxDebugDump, ctx->handle);
    Py_END_ALLOW_THREADS;
    if (rv < 0) {
        PyXmlSec_SetLastError("failed to encrypt binary");
        goto ON_FAIL;
    }

    result = pyxmlsec_dump_doc(doc);

ON_FAIL:
    if (doc != NULL) xmlFreeDoc(doc);
    return result;
}

// _encrypt_uri(template_bytes, uri) -> bytes
static const char PyXmlSec_EncryptionContext_EncryptUri__doc__[] = \
    "_encrypt_uri(template_bytes, uri) -> bytes\n"
    "Internal: encrypt the contents of ``uri`` into a fragment-shaped EncryptedData template.\n";
static PyObject* PyXmlSec_EncryptionContext_EncryptUri(PyObject* self, PyObject* args, PyObject* kwargs) {
    static char *kwlist[] = { "template_bytes", "uri", NULL };
    PyXmlSec_EncryptionContext* ctx = (PyXmlSec_EncryptionContext*)self;
    const char* tmpl = NULL;
    Py_ssize_t tmpl_len = 0;
    const char* uri = NULL;
    xmlDocPtr doc = NULL;
    xmlNodePtr template_root;
    PyObject* result = NULL;
    int rv;

    if (!PyArg_ParseTupleAndKeywords(args, kwargs, "y#s:_encrypt_uri", kwlist,
        &tmpl, &tmpl_len, &uri))
    {
        goto ON_FAIL;
    }

    doc = pyxmlsec_load_doc(tmpl, tmpl_len, NULL);
    if (doc == NULL) goto ON_FAIL;
    template_root = xmlDocGetRootElement(doc);
    if (template_root == NULL) {
        PyErr_SetString(PyXmlSec_Error, "template fragment has no root element");
        goto ON_FAIL;
    }

    Py_BEGIN_ALLOW_THREADS;
    rv = xmlSecEncCtxUriEncrypt(ctx->handle, template_root, (const xmlSecByte*)uri);
    PYXMLSEC_DUMP(xmlSecEncCtxDebugDump, ctx->handle);
    Py_END_ALLOW_THREADS;
    if (rv < 0) {
        PyXmlSec_SetLastError("failed to encrypt URI");
        goto ON_FAIL;
    }

    result = pyxmlsec_dump_doc(doc);

ON_FAIL:
    if (doc != NULL) xmlFreeDoc(doc);
    return result;
}

// _encrypt_xml(node_doc_bytes, base_url_or_none, template_path_or_none,
//              node_path, template_bytes_or_none) -> bytes
//
// Mirrors the existing C version: when template_path is set the template
// already lives inside node_doc_bytes (same-tree), and we resolve it via
// the path. When template_bytes is set, the template lives in a
// standalone fragment that we parse separately and copy into node's doc
// via xmlDocCopyNode (matches src/enc.c:264 logic). Exactly one of the
// two must be non-None.
static const char PyXmlSec_EncryptionContext_EncryptXml__doc__[] = \
    "_encrypt_xml(node_doc_bytes, base_url, template_path, node_path, template_bytes) -> bytes\n"
    "Internal: encrypt node at node_path inside node_doc_bytes using the template (attached or detached).\n";
static PyObject* PyXmlSec_EncryptionContext_EncryptXml(PyObject* self, PyObject* args, PyObject* kwargs) {
    static char *kwlist[] = { "node_doc_bytes", "base_url", "template_path", "node_path", "template_bytes", NULL };
    PyXmlSec_EncryptionContext* ctx = (PyXmlSec_EncryptionContext*)self;
    const char* xml = NULL;
    Py_ssize_t xml_len = 0;
    PyObject* base_url_obj = NULL;
    PyObject* template_path = NULL;
    PyObject* node_path = NULL;
    PyObject* template_bytes_obj = NULL;
    xmlDocPtr node_doc = NULL;
    xmlDocPtr tmpl_doc = NULL;
    xmlNodePtr tmpl_node = NULL;
    xmlNodePtr copied = NULL;
    xmlNodePtr node = NULL;
    PyObject* result = NULL;
    const char* base_url = NULL;
    int rv;

    if (!PyArg_ParseTupleAndKeywords(args, kwargs, "y#OOOO:_encrypt_xml", kwlist,
        &xml, &xml_len, &base_url_obj, &template_path, &node_path, &template_bytes_obj))
    {
        goto ON_FAIL;
    }
    if (base_url_obj != Py_None) {
        base_url = PyUnicode_AsUTF8(base_url_obj);
        if (base_url == NULL) goto ON_FAIL;
    }

    node_doc = pyxmlsec_load_doc(xml, xml_len, base_url);
    if (node_doc == NULL) goto ON_FAIL;

    node = pyxmlsec_resolve_path(node_doc, node_path);
    if (node == NULL) goto ON_FAIL;

    if (template_bytes_obj != Py_None) {
        // Detached template: parse the standalone fragment and copy its
        // root into the node's doc. Mirrors xmlDocCopyNode at the old
        // src/enc.c:264.
        const char* tmpl_xml = NULL;
        Py_ssize_t tmpl_len = 0;
        if (PyBytes_AsStringAndSize(template_bytes_obj, (char**)&tmpl_xml, &tmpl_len) < 0) goto ON_FAIL;
        tmpl_doc = pyxmlsec_load_doc(tmpl_xml, tmpl_len, NULL);
        if (tmpl_doc == NULL) goto ON_FAIL;
        xmlNodePtr tmpl_root = xmlDocGetRootElement(tmpl_doc);
        if (tmpl_root == NULL) {
            PyErr_SetString(PyXmlSec_Error, "template fragment has no root element");
            goto ON_FAIL;
        }
        copied = xmlDocCopyNode(tmpl_root, node_doc, 1);
        if (copied == NULL) {
            PyErr_SetString(PyXmlSec_InternalError, "could not copy template tree");
            goto ON_FAIL;
        }
        tmpl_node = copied;
    } else if (template_path != Py_None) {
        // Attached template: resolve its path inside node_doc.
        tmpl_node = pyxmlsec_resolve_path(node_doc, template_path);
        if (tmpl_node == NULL) goto ON_FAIL;
    } else {
        PyErr_SetString(PyExc_TypeError, "_encrypt_xml requires either template_path or template_bytes");
        goto ON_FAIL;
    }

    Py_BEGIN_ALLOW_THREADS;
    rv = xmlSecEncCtxXmlEncrypt(ctx->handle, tmpl_node, node);
    PYXMLSEC_DUMP(xmlSecEncCtxDebugDump, ctx->handle);
    Py_END_ALLOW_THREADS;
    if (rv < 0) {
        if (copied != NULL) {
            // xmlsec attaches `copied` into the doc on success; on failure it
            // was either freed already or still detached. Be defensive.
            // (xmlSecEncCtxXmlEncrypt's docs are unclear; in practice freeing
            // here is safe because copied was never inserted.)
            xmlFreeNode(copied);
            copied = NULL;
        }
        PyXmlSec_SetLastError("failed to encrypt xml");
        goto ON_FAIL;
    }

    result = pyxmlsec_dump_doc(node_doc);

ON_FAIL:
    if (tmpl_doc != NULL) xmlFreeDoc(tmpl_doc);
    if (node_doc != NULL) xmlFreeDoc(node_doc);
    return result;
}

// release the replaced nodes in a way safe for `lxml`
static void PyXmlSec_ClearReplacedNodes(xmlSecEncCtxPtr ctx, PyXmlSec_LxmlDocumentPtr doc) {
    PyXmlSec_LxmlElementPtr elem;
    // release the replaced nodes in a way safe for `lxml`
    xmlNodePtr n = ctx->replacedNodeList;
    xmlNodePtr nn;

    while (n != NULL) {
        PYXMLSEC_DEBUGF("clear replaced node %p", n);
        nn = n->next;
        // if n has references, it will not be deleted
        elem = (PyXmlSec_LxmlElementPtr)PyXmlSec_elementFactory(doc, n);
        if (NULL == elem)
            xmlFreeNode(n);
        else
            Py_DECREF(elem);
        n = nn;
    }
    ctx->replacedNodeList = NULL;
}

static const char PyXmlSec_EncryptionContextDecrypt__doc__[] = \
    "decrypt(node)\n"
    "Decrypts ``node`` (an ``EncryptedData`` or ``EncryptedKey`` element) and returns the result. "
    "The decryption may result in binary data or an XML subtree. "
    "In the former case, the binary data is returned. In the latter case, "
    "the input tree is modified and a reference to the decrypted XML subtree is returned.\n"
    "If the operation modifies the tree, it removes replaced nodes.\n\n"
    ":param node: the pointer to :xml:`<enc:EncryptedData/>` or :xml:`<enc:EncryptedKey/>` node\n"
    ":type node: :class:`lxml.etree._Element`\n"
    ":return: depends on input parameters\n"
    ":rtype: :class:`lxml.etree._Element` or :class:`bytes`";
static PyObject* PyXmlSec_EncryptionContextDecrypt(PyObject* self, PyObject* args, PyObject* kwargs) {
    static char *kwlist[] = { "node", NULL};

    PyXmlSec_EncryptionContext* ctx = (PyXmlSec_EncryptionContext*)self;
    PyXmlSec_LxmlElementPtr node = NULL;

    PyObject* node_num = NULL;
    PyObject* parent = NULL;

    PyObject* tmp;
    xmlNodePtr root;
    xmlNodePtr xparent;
    int rv;
    xmlChar* ttype;
    int notContent;

    PYXMLSEC_DEBUGF("%p: decrypt - start", self);
    if (!PyArg_ParseTupleAndKeywords(args, kwargs, "O&:decrypt", kwlist, PyXmlSec_LxmlElementConverter, &node)) {
        goto ON_FAIL;
    }

    xparent = node->_c_node->parent;
    if (xparent != NULL && !PyXmlSec_IsElement(xparent)) {
        xparent = NULL;
    }

    if (xparent != NULL) {
        parent = (PyObject*)PyXmlSec_elementFactory(node->_doc, xparent);
        if (parent == NULL) {
            PyErr_SetString(PyXmlSec_InternalError, "failed to construct parent");
            goto ON_FAIL;
        }
        // get index of node
        node_num = PyObject_CallMethod(parent, "index", "O", node);
        PYXMLSEC_DEBUGF("parent: %p, %p", parent, node_num);
    }

    Py_BEGIN_ALLOW_THREADS;
    ctx->handle->flags = XMLSEC_ENC_RETURN_REPLACED_NODE;
    ctx->handle->mode = xmlSecCheckNodeName(node->_c_node, xmlSecNodeEncryptedKey, xmlSecEncNs) ? xmlEncCtxModeEncryptedKey : xmlEncCtxModeEncryptedData;
    PYXMLSEC_DEBUGF("mode: %d", ctx->handle->mode);
    rv = xmlSecEncCtxDecrypt(ctx->handle, node->_c_node);
    PYXMLSEC_DUMP(xmlSecEncCtxDebugDump, ctx->handle);
    Py_END_ALLOW_THREADS;

    PyXmlSec_ClearReplacedNodes(ctx->handle, node->_doc);

    if (rv < 0) {
        PyXmlSec_SetLastError("failed to decrypt");
        goto ON_FAIL;
    }

    if (!ctx->handle->resultReplaced) {
        Py_XDECREF(node_num);
        Py_XDECREF(parent);
        PYXMLSEC_DEBUGF("%p: binary.decrypt - ok", self);
        return PyBytes_FromStringAndSize(
            (const char*)xmlSecBufferGetData(ctx->handle->result),
            (Py_ssize_t)xmlSecBufferGetSize(ctx->handle->result)
        );
    }

    if (xparent != NULL) {
        ttype = xmlGetProp(node->_c_node, XSTR("Type"));
        notContent = (ttype == NULL || !xmlStrEqual(ttype, xmlSecTypeEncContent));
        xmlFree(ttype);

        if (notContent) {
            tmp = PyObject_GetItem(parent, node_num);
            if (tmp == NULL) goto ON_FAIL;
            Py_DECREF(parent);
            parent = tmp;
        }
        Py_DECREF(node_num);
        PYXMLSEC_DEBUGF("%p: parent.decrypt - ok", self);
        return parent;
    }

    // root has been replaced
    root = xmlDocGetRootElement(node->_doc->_c_doc);
    if (root == NULL) {
        PyErr_SetString(PyXmlSec_Error, "decryption resulted in a non well formed document");
        goto ON_FAIL;
    }

    Py_XDECREF(node_num);
    Py_XDECREF(parent);

    PYXMLSEC_DEBUGF("%p: decrypt - ok", self);
    return (PyObject*)PyXmlSec_elementFactory(node->_doc, root);

ON_FAIL:
    PYXMLSEC_DEBUGF("%p: decrypt - fail", self);
    Py_XDECREF(node_num);
    Py_XDECREF(parent);
    return NULL;
}

static PyGetSetDef PyXmlSec_EncryptionContextGetSet[] = {
    {
        "key",
        (getter)PyXmlSec_EncryptionContextKeyGet,
        (setter)PyXmlSec_EncryptionContextKeySet,
        (char*)PyXmlSec_EncryptionContextKey__doc__,
        NULL
    },
    {NULL} /* Sentinel */
};

static PyMethodDef PyXmlSec_EncryptionContextMethods[] = {
    {
        "reset",
        (PyCFunction)PyXmlSec_EncryptionContextReset,
        METH_NOARGS,
        PyXmlSec_EncryptionContextReset__doc__,
    },
    {
        "_encrypt_binary",
        (PyCFunction)PyXmlSec_EncryptionContext_EncryptBinary,
        METH_VARARGS|METH_KEYWORDS,
        PyXmlSec_EncryptionContext_EncryptBinary__doc__,
    },
    {
        "_encrypt_xml",
        (PyCFunction)PyXmlSec_EncryptionContext_EncryptXml,
        METH_VARARGS|METH_KEYWORDS,
        PyXmlSec_EncryptionContext_EncryptXml__doc__,
    },
    {
        "_encrypt_uri",
        (PyCFunction)PyXmlSec_EncryptionContext_EncryptUri,
        METH_VARARGS|METH_KEYWORDS,
        PyXmlSec_EncryptionContext_EncryptUri__doc__,
    },
    {
        "decrypt",
        (PyCFunction)PyXmlSec_EncryptionContextDecrypt,
        METH_VARARGS|METH_KEYWORDS,
        PyXmlSec_EncryptionContextDecrypt__doc__
    },
    {NULL, NULL} /* sentinel */
};

static PyTypeObject _PyXmlSec_EncryptionContextType = {
    PyVarObject_HEAD_INIT(NULL, 0)
    MODULE_TYPE_PREFIX ".EncryptionContext",    /* tp_name */
    sizeof(PyXmlSec_EncryptionContext),          /* tp_basicsize */
    0,                                           /* tp_itemsize */
    PyXmlSec_EncryptionContext__del__,           /* tp_dealloc */
    0,                                           /* tp_print */
    0,                                           /* tp_getattr */
    0,                                           /* tp_setattr */
    0,                                           /* tp_reserved */
    0,                                           /* tp_repr */
    0,                                           /* tp_as_number */
    0,                                           /* tp_as_sequence */
    0,                                           /* tp_as_mapping */
    0,                                           /* tp_hash  */
    0,                                           /* tp_call */
    0,                                           /* tp_str */
    0,                                           /* tp_getattro */
    0,                                           /* tp_setattro */
    0,                                           /* tp_as_buffer */
    Py_TPFLAGS_DEFAULT|Py_TPFLAGS_BASETYPE,      /* tp_flags */
    "XML Encryption implementation",             /* tp_doc */
    0,                                           /* tp_traverse */
    0,                                           /* tp_clear */
    0,                                           /* tp_richcompare */
    0,                                           /* tp_weaklistoffset */
    0,                                           /* tp_iter */
    0,                                           /* tp_iternext */
    PyXmlSec_EncryptionContextMethods,           /* tp_methods */
    0,                                           /* tp_members */
    PyXmlSec_EncryptionContextGetSet,            /* tp_getset */
    0,                                           /* tp_base */
    0,                                           /* tp_dict */
    0,                                           /* tp_descr_get */
    0,                                           /* tp_descr_set */
    0,                                           /* tp_dictoffset */
    PyXmlSec_EncryptionContext__init__,          /* tp_init */
    0,                                           /* tp_alloc */
    PyXmlSec_EncryptionContext__new__,           /* tp_new */
    0                                            /* tp_free */
};

PyTypeObject* PyXmlSec_EncryptionContextType = &_PyXmlSec_EncryptionContextType;

int PyXmlSec_EncModule_Init(PyObject* package) {
    if (PyType_Ready(PyXmlSec_EncryptionContextType) < 0) goto ON_FAIL;

    PYXMLSEC_DEBUGF("%p", PyXmlSec_EncryptionContextType);
    // since objects is created as static objects, need to increase refcount to prevent deallocate
    Py_INCREF(PyXmlSec_EncryptionContextType);

    if (PyModule_AddObject(package, "EncryptionContext", (PyObject*)PyXmlSec_EncryptionContextType) < 0) goto ON_FAIL;
    return 0;
ON_FAIL:
    return -1;
}
