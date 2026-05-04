// Copyright (c) 2017 Ryan Leckey
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

// find_child / find_parent / find_node moved to pure-Python xmlsec/tree.py.
// Only add_ids remains here; it will move to Python in a later PR (it touches
// the libxml2 ID table and needs a coordinated migration with sign/verify).

#include "common.h"
#include "utils.h"
#include "lxml.h"

#include <xmlsec/xmltree.h>

#define PYXMLSEC_TREE_DOC "Common XML utility functions"

static char PyXmlSec_TreeAddIds__doc__[] = \
    "add_ids(node, ids) -> None\n"
    "Registers ``ids`` as ids used below ``node``. ``ids`` is a sequence of attribute names "\
    "used as XML ids in the subtree rooted at ``node``.\n"\
    "A call to :func:`~.add_ids` may be necessary to make known which attributes contain XML ids.\n"\
    "This is the case, if a transform references an id via ``XPointer`` or a self document uri and "
    "the id inkey_data_formation is not available by other means (e.g. an associated DTD or XML schema).\n\n"
    ":param node: the pointer to XML node\n"
    ":type node: :class:`lxml.etree._Element`\n"
    ":param ids: the list of ID attributes.\n"
    ":type ids: :class:`list` of strings";
static PyObject* PyXmlSec_TreeAddIds(PyObject* self, PyObject *args, PyObject *kwargs) {
    static char *kwlist[] = { "node", "ids", NULL};

    PyXmlSec_LxmlElementPtr node = NULL;
    PyObject* ids = NULL;

    const xmlChar** list = NULL;

    Py_ssize_t n;
    PyObject* tmp;
    PyObject* key;
    Py_ssize_t i;

    PYXMLSEC_DEBUG("tree add_ids - start");
    if (!PyArg_ParseTupleAndKeywords(args, kwargs, "O&O:add_ids", kwlist, PyXmlSec_LxmlElementConverter, &node, &ids))
    {
        goto ON_FAIL;
    }
    n = PyObject_Length(ids);
    if (n < 0) goto ON_FAIL;

    list = (const xmlChar**)xmlMalloc(sizeof(xmlChar*) * (n + 1));
    if (list == NULL) {
        PyErr_SetString(PyExc_MemoryError, "no memory");
        goto ON_FAIL;
    }

    for (i = 0; i < n; ++i) {
        key = PyLong_FromSsize_t(i);
        if (key == NULL) goto ON_FAIL;
        tmp = PyObject_GetItem(ids, key);
        Py_DECREF(key);
        if (tmp == NULL) goto ON_FAIL;
        list[i] = XSTR(PyUnicode_AsUTF8(tmp));
        Py_DECREF(tmp);
        if (list[i] == NULL) goto ON_FAIL;
    }
    list[n] = NULL;

    Py_BEGIN_ALLOW_THREADS;
    xmlSecAddIDs(node->_doc->_c_doc, node->_c_node, list);
    Py_END_ALLOW_THREADS;

    PyMem_Free(list);

    PYXMLSEC_DEBUG("tree add_ids - ok");
    Py_RETURN_NONE;
ON_FAIL:
    PYXMLSEC_DEBUG("tree add_ids - fail");
    xmlFree(list);
    return NULL;
}

static PyMethodDef PyXmlSec_TreeMethods[] = {
    {
        "add_ids",
        (PyCFunction)PyXmlSec_TreeAddIds,
        METH_VARARGS|METH_KEYWORDS,
        PyXmlSec_TreeAddIds__doc__,
    },
    {NULL, NULL} /* sentinel */
};

static PyModuleDef PyXmlSec_TreeModule =
{
    PyModuleDef_HEAD_INIT,
    MODULE_FULL_NAME ".tree",
    PYXMLSEC_TREE_DOC,
    -1,
    PyXmlSec_TreeMethods,     /* m_methods */
    NULL,                     /* m_slots */
    NULL,                     /* m_traverse */
    NULL,                     /* m_clear */
    NULL,                     /* m_free */
};


int PyXmlSec_TreeModule_Init(PyObject* package) {
    PyObject* tree = PyModule_Create(&PyXmlSec_TreeModule);

    if (!tree) goto ON_FAIL;

    if (PyModule_AddObject(package, "tree", tree) < 0) goto ON_FAIL;

    return 0;
ON_FAIL:
    Py_XDECREF(tree);
    return -1;
}
