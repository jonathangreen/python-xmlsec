// Copyright (c) 2017 Ryan Leckey
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

#ifndef __PYXMLSEC_VERSION_H__
#define __PYXMLSEC_VERSION_H__

// libxml2 version accessors split out from the (now-removed) lxml.c.
// Both runtime (xmlParserVersion) and compile-time (LIBXML_VERSION) are
// useful for diagnostics: xmlsec.get_libxml_version() and
// xmlsec.get_libxml_compiled_version() expose them respectively.

long PyXmlSec_GetLibXmlVersionMajor(void);
long PyXmlSec_GetLibXmlVersionMinor(void);
long PyXmlSec_GetLibXmlVersionPatch(void);

long PyXmlSec_GetLibXmlCompiledVersionMajor(void);
long PyXmlSec_GetLibXmlCompiledVersionMinor(void);
long PyXmlSec_GetLibXmlCompiledVersionPatch(void);

#endif // __PYXMLSEC_VERSION_H__
