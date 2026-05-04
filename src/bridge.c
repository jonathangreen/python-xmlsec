// Copyright (c) 2026 python-xmlsec contributors
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
#include "bridge.h"

#include <libxml/parser.h>
#include <libxml/tree.h>
#include <libxml/valid.h>

xmlDocPtr pyxmlsec_load_doc(const char* xml, Py_ssize_t len, const char* base_url) {
    xmlDocPtr doc = xmlReadMemory(xml, (int)len, base_url, "UTF-8",
        XML_PARSE_NONET | XML_PARSE_NOWARNING | XML_PARSE_NOERROR);
    if (doc == NULL) {
        PyXmlSec_SetLastError("failed to parse XML document");
        return NULL;
    }
    return doc;
}

PyObject* pyxmlsec_dump_doc(xmlDocPtr doc) {
    xmlChar* buf = NULL;
    int size = 0;

    xmlDocDumpMemory(doc, &buf, &size);
    if (buf == NULL) {
        PyErr_SetString(PyXmlSec_Error, "failed to serialize document");
        return NULL;
    }
    PyObject* result = PyBytes_FromStringAndSize((const char*)buf, (Py_ssize_t)size);
    xmlFree(buf);
    return result;
}

// Walk the doc's element children by structural index.
// path == [] returns the root element. path == [0] returns the first
// element child of root, path == [0, 2] returns its third element
// child, etc. Non-element nodes (text, comments, PIs) are skipped.
xmlNodePtr pyxmlsec_resolve_path(xmlDocPtr doc, PyObject* index_list) {
    xmlNodePtr cur = xmlDocGetRootElement(doc);
    if (cur == NULL) {
        PyErr_SetString(PyXmlSec_Error, "document has no root element");
        return NULL;
    }
    if (!PyList_Check(index_list)) {
        PyErr_SetString(PyExc_TypeError, "structural path must be a list of integers");
        return NULL;
    }

    Py_ssize_t n = PyList_Size(index_list);
    for (Py_ssize_t i = 0; i < n; i++) {
        PyObject* idx_obj = PyList_GetItem(index_list, i); // borrowed
        if (idx_obj == NULL) return NULL;
        long idx = PyLong_AsLong(idx_obj);
        if (idx < 0 || PyErr_Occurred()) {
            if (!PyErr_Occurred()) {
                PyErr_SetString(PyExc_ValueError, "structural path indexes must be non-negative");
            }
            return NULL;
        }

        xmlNodePtr child = cur->children;
        long counter = 0;
        xmlNodePtr matched = NULL;
        while (child != NULL) {
            if (child->type == XML_ELEMENT_NODE) {
                if (counter == idx) {
                    matched = child;
                    break;
                }
                counter++;
            }
            child = child->next;
        }
        if (matched == NULL) {
            PyErr_Format(PyXmlSec_Error,
                "structural path index %ld out of range at depth %ld",
                idx, (long)i);
            return NULL;
        }
        cur = matched;
    }
    return cur;
}

int pyxmlsec_apply_id_specs(xmlDocPtr doc, PyObject* spec_list) {
    if (!PyList_Check(spec_list)) {
        PyErr_SetString(PyExc_TypeError, "id specs must be a list of (path, attr, ns) tuples");
        return -1;
    }

    Py_ssize_t n = PyList_Size(spec_list);
    for (Py_ssize_t i = 0; i < n; i++) {
        PyObject* spec = PyList_GetItem(spec_list, i); // borrowed
        if (spec == NULL) return -1;
        if (!PyTuple_Check(spec) || PyTuple_Size(spec) != 3) {
            PyErr_SetString(PyExc_TypeError, "id spec must be a (path, attr, ns_or_None) tuple");
            return -1;
        }

        PyObject* path = PyTuple_GetItem(spec, 0);
        PyObject* attr_obj = PyTuple_GetItem(spec, 1);
        PyObject* ns_obj = PyTuple_GetItem(spec, 2);

        const char* attr_name = PyUnicode_AsUTF8(attr_obj);
        if (attr_name == NULL) return -1;
        const char* ns = NULL;
        if (ns_obj != Py_None) {
            ns = PyUnicode_AsUTF8(ns_obj);
            if (ns == NULL) return -1;
        }

        xmlNodePtr elem = pyxmlsec_resolve_path(doc, path);
        if (elem == NULL) return -1;

        xmlAttrPtr attr;
        if (ns != NULL) {
            attr = xmlHasNsProp(elem, XSTR(attr_name), XSTR(ns));
        } else {
            attr = xmlHasProp(elem, XSTR(attr_name));
        }
        if (attr == NULL || attr->children == NULL) {
            PyErr_SetString(PyXmlSec_Error, "missing attribute.");
            return -1;
        }

        xmlChar* value = xmlNodeListGetString(doc, attr->children, 1);
        if (value == NULL) {
            PyErr_SetString(PyXmlSec_Error, "could not read id attribute value");
            return -1;
        }

        // Match src/ds.c:161-167: same attr is a no-op, different attr is
        // a duplicate, no existing registration is the new path.
        xmlAttrPtr existing = xmlGetID(doc, value);
        if (existing == attr) {
            xmlFree(value);
            continue;
        }
        if (existing != NULL) {
            xmlFree(value);
            PyErr_SetString(PyXmlSec_Error, "duplicated id.");
            return -1;
        }
        xmlAddID(NULL, doc, value, attr);
        xmlFree(value);
    }
    return 0;
}
