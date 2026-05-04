// Copyright (c) 2026 python-xmlsec contributors
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

// Bridge primitives shared by the bytes-based crypto entry points (sign,
// verify, encrypt, decrypt). These functions stay strictly on
// python-xmlsec's libxml2 side: they take Python bytes / index lists in
// and produce Python bytes / xmlNodePtrs out, without ever touching an
// lxml-owned xmlNodePtr.

#ifndef __PYXMLSEC_BRIDGE_H__
#define __PYXMLSEC_BRIDGE_H__

#include "platform.h"

#include <libxml/tree.h>

// Parse XML bytes into a freshly-owned xmlDocPtr using python-xmlsec's
// libxml2. ``base_url`` is forwarded to xmlReadMemory; pass NULL if none.
// On failure returns NULL with a Python exception set.
xmlDocPtr pyxmlsec_load_doc(const char* xml, Py_ssize_t len, const char* base_url);

// Serialize ``doc`` to a Python bytes object via xmlDocDumpMemory.
// Returns NULL with a Python exception set on failure.
PyObject* pyxmlsec_dump_doc(xmlDocPtr doc);

// Resolve a structural index path (Python list of ints) into a node of
// ``doc``. Each index addresses element-only children of the previous
// node; an empty list returns the document root. Returns NULL with a
// Python exception set if the path doesn't resolve.
xmlNodePtr pyxmlsec_resolve_path(xmlDocPtr doc, PyObject* index_list);

// Apply a list of (path, attr_name, attr_ns_or_None) id specs against
// ``doc`` by calling xmlAddID for each matching attribute. Mirrors
// SignatureContext.register_id semantics from src/ds.c:131-180:
// raises xmlsec.Error("missing attribute.") if attr is absent,
// xmlsec.Error("duplicated id.") if a different attr is already
// registered with the same id value, no-ops if the same attr is already
// registered. Returns 0 on success, -1 with a Python exception on
// failure.
int pyxmlsec_apply_id_specs(xmlDocPtr doc, PyObject* spec_list);

#endif // __PYXMLSEC_BRIDGE_H__
