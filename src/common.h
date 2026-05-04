// Copyright (c) 2017 Ryan Leckey
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

#ifndef __PYXMLSEC_COMMON_H__
#define __PYXMLSEC_COMMON_H__

#include "debug.h"

// MODULE_PACKAGE_NAME is the user-visible top-level package (e.g. xmlsec).
// MODULE_INIT_NAME is the C-extension submodule name (e.g. _impl) — used for
// PyInit_<name> and as the trailing component of the dotted module name.
#ifndef MODULE_PACKAGE_NAME
#define MODULE_PACKAGE_NAME xmlsec
#endif
#ifndef MODULE_INIT_NAME
#define MODULE_INIT_NAME _impl
#endif

#define JOIN(X,Y) DO_JOIN1(X,Y)
#define DO_JOIN1(X,Y) DO_JOIN2(X,Y)
#define DO_JOIN2(X,Y) X##Y

#define DO_STRINGIFY(x) #x
#define STRINGIFY(x) DO_STRINGIFY(x)

// Dotted Python module name: "xmlsec._impl"
#define MODULE_FULL_NAME STRINGIFY(MODULE_PACKAGE_NAME) "." STRINGIFY(MODULE_INIT_NAME)
// User-visible package name: "xmlsec" — used as the prefix for type repr names so
// Python users see e.g. "xmlsec.SignatureContext" rather than "xmlsec._impl.SignatureContext".
#define MODULE_TYPE_PREFIX STRINGIFY(MODULE_PACKAGE_NAME)

#endif //__PYXMLSEC_COMMON_H__
