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

static xmlSecEncCtxPtr PyXmlSec_EncryptionContextCreateOperationContext(PyXmlSec_EncryptionContext* ctx) {
    xmlSecEncCtxPtr op_ctx = xmlSecEncCtxCreate(ctx->manager != NULL ? ctx->manager->handle : NULL);
    if (op_ctx == NULL) {
        PyXmlSec_SetLastError("failed to create the encryption context");
        return NULL;
    }

    op_ctx->keyInfoReadCtx.flags = ctx->handle->keyInfoReadCtx.flags;
    op_ctx->keyInfoWriteCtx.flags = ctx->handle->keyInfoWriteCtx.flags;

    if (ctx->handle->encKey != NULL) {
        op_ctx->encKey = xmlSecKeyDuplicate(ctx->handle->encKey);
        if (op_ctx->encKey == NULL) {
            xmlSecEncCtxDestroy(op_ctx);
            PyXmlSec_SetLastError("failed to duplicate key");
            return NULL;
        }
    }

    return op_ctx;
}

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
    xmlSecEncCtxPtr op_ctx = NULL;
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
    op_ctx = PyXmlSec_EncryptionContextCreateOperationContext(ctx);
    if (op_ctx == NULL) goto ON_FAIL;

    Py_BEGIN_ALLOW_THREADS;
    rv = xmlSecEncCtxBinaryEncrypt(op_ctx, template_root, (const xmlSecByte*)data, (xmlSecSize)data_size);
    PYXMLSEC_DUMP(xmlSecEncCtxDebugDump, op_ctx);
    Py_END_ALLOW_THREADS;
    if (rv < 0) {
        PyXmlSec_SetLastError("failed to encrypt binary");
        goto ON_FAIL;
    }

    result = pyxmlsec_dump_doc(doc);

ON_FAIL:
    if (op_ctx != NULL) xmlSecEncCtxDestroy(op_ctx);
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
    xmlSecEncCtxPtr op_ctx = NULL;
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
    op_ctx = PyXmlSec_EncryptionContextCreateOperationContext(ctx);
    if (op_ctx == NULL) goto ON_FAIL;

    Py_BEGIN_ALLOW_THREADS;
    rv = xmlSecEncCtxUriEncrypt(op_ctx, template_root, (const xmlSecByte*)uri);
    PYXMLSEC_DUMP(xmlSecEncCtxDebugDump, op_ctx);
    Py_END_ALLOW_THREADS;
    if (rv < 0) {
        PyXmlSec_SetLastError("failed to encrypt URI");
        goto ON_FAIL;
    }

    result = pyxmlsec_dump_doc(doc);

ON_FAIL:
    if (op_ctx != NULL) xmlSecEncCtxDestroy(op_ctx);
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
    xmlSecEncCtxPtr op_ctx = NULL;
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
    op_ctx = PyXmlSec_EncryptionContextCreateOperationContext(ctx);
    if (op_ctx == NULL) goto ON_FAIL;

    Py_BEGIN_ALLOW_THREADS;
    rv = xmlSecEncCtxXmlEncrypt(op_ctx, tmpl_node, node);
    PYXMLSEC_DUMP(xmlSecEncCtxDebugDump, op_ctx);
    Py_END_ALLOW_THREADS;
    if (rv < 0) {
        // ``copied`` was created via xmlDocCopyNode(..., node_doc, ...), so
        // node_doc tracks the node either as part of its tree (if xmlsec
        // attached it before failing) or as an unreferenced free node (if
        // xmlsec freed its own reference but left node_doc owning it). In
        // both cases ``xmlFreeDoc(node_doc)`` below cleans up correctly.
        // Calling xmlFreeNode(copied) explicitly here would risk a
        // double-free in the first case.
        PyXmlSec_SetLastError("failed to encrypt xml");
        goto ON_FAIL;
    }

    result = pyxmlsec_dump_doc(node_doc);

ON_FAIL:
    if (op_ctx != NULL) xmlSecEncCtxDestroy(op_ctx);
    if (tmpl_doc != NULL) xmlFreeDoc(tmpl_doc);
    if (node_doc != NULL) xmlFreeDoc(node_doc);
    return result;
}

// _decrypt(xml_bytes, base_url_or_none, node_path, id_specs) -> ("bytes", payload) | ("xml", new_doc_bytes)
//
// Bytes-based replacement for the old tree-taking decrypt: parse with
// python-xmlsec's libxml2, run xmlSecEncCtxDecrypt at node_path, and
// return a tagged tuple. The Python wrapper splices the result back
// into the user's lxml tree.
static const char PyXmlSec_EncryptionContext_Decrypt__doc__[] = \
    "_decrypt(xml_bytes, base_url, node_path, id_specs) -> (kind, payload)\n"
    "Internal: decrypt the EncryptedData/EncryptedKey at node_path.\n"
    "kind is 'bytes' (payload is the decrypted bytes) or 'xml' (payload is the modified doc bytes).\n";
static PyObject* PyXmlSec_EncryptionContext_Decrypt(PyObject* self, PyObject* args, PyObject* kwargs) {
    static char *kwlist[] = { "xml_bytes", "base_url", "node_path", "id_specs", NULL };
    PyXmlSec_EncryptionContext* ctx = (PyXmlSec_EncryptionContext*)self;
    const char* xml = NULL;
    Py_ssize_t xml_len = 0;
    PyObject* base_url_obj = NULL;
    PyObject* node_path = NULL;
    PyObject* id_specs = NULL;
    xmlSecEncCtxPtr op_ctx = NULL;
    xmlDocPtr doc = NULL;
    xmlNodePtr node;
    PyObject* result = NULL;
    const char* base_url = NULL;
    int rv;

    if (!PyArg_ParseTupleAndKeywords(args, kwargs, "y#OO!O!:_decrypt", kwlist,
        &xml, &xml_len, &base_url_obj, &PyList_Type, &node_path, &PyList_Type, &id_specs))
    {
        goto ON_FAIL;
    }
    if (base_url_obj != Py_None) {
        base_url = PyUnicode_AsUTF8(base_url_obj);
        if (base_url == NULL) goto ON_FAIL;
    }

    doc = pyxmlsec_load_doc(xml, xml_len, base_url);
    if (doc == NULL) goto ON_FAIL;

    if (PyList_Size(id_specs) > 0 && pyxmlsec_apply_id_specs(doc, id_specs) < 0) goto ON_FAIL;

    node = pyxmlsec_resolve_path(doc, node_path);
    if (node == NULL) goto ON_FAIL;
    op_ctx = PyXmlSec_EncryptionContextCreateOperationContext(ctx);
    if (op_ctx == NULL) goto ON_FAIL;

    Py_BEGIN_ALLOW_THREADS;
    op_ctx->mode = xmlSecCheckNodeName(node, xmlSecNodeEncryptedKey, xmlSecEncNs)
        ? xmlEncCtxModeEncryptedKey
        : xmlEncCtxModeEncryptedData;
    rv = xmlSecEncCtxDecrypt(op_ctx, node);
    PYXMLSEC_DUMP(xmlSecEncCtxDebugDump, op_ctx);
    Py_END_ALLOW_THREADS;

    if (rv < 0) {
        PyXmlSec_SetLastError("failed to decrypt");
        goto ON_FAIL;
    }

    if (!op_ctx->resultReplaced) {
        // Binary decryption: return ("bytes", payload).
        PyObject* payload = PyBytes_FromStringAndSize(
            (const char*)xmlSecBufferGetData(op_ctx->result),
            (Py_ssize_t)xmlSecBufferGetSize(op_ctx->result));
        if (payload == NULL) goto ON_FAIL;
        result = Py_BuildValue("(sO)", "bytes", payload);
        Py_DECREF(payload);
    } else {
        // XML decryption: serialize the modified doc and return ("xml", bytes).
        PyObject* payload = pyxmlsec_dump_doc(doc);
        if (payload == NULL) goto ON_FAIL;
        result = Py_BuildValue("(sO)", "xml", payload);
        Py_DECREF(payload);
    }

ON_FAIL:
    if (op_ctx != NULL) xmlSecEncCtxDestroy(op_ctx);
    if (doc != NULL) xmlFreeDoc(doc);
    return result;
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
        "_decrypt",
        (PyCFunction)PyXmlSec_EncryptionContext_Decrypt,
        METH_VARARGS|METH_KEYWORDS,
        PyXmlSec_EncryptionContext_Decrypt__doc__,
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
