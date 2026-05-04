// Copyright (c) 2017 Ryan Leckey
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

#include "platform.h"
#include "version.h"

#include <libxml/xmlversion.h>
#include <libxml/parser.h>

#define XMLSEC_EXTRACT_VERSION(x, y) ((x / (y)) % 100)
#define XMLSEC_EXTRACT_MAJOR(x) XMLSEC_EXTRACT_VERSION(x, 100 * 100)
#define XMLSEC_EXTRACT_MINOR(x) XMLSEC_EXTRACT_VERSION(x, 100)
#define XMLSEC_EXTRACT_PATCH(x) XMLSEC_EXTRACT_VERSION(x, 1)

static long PyXmlSec_GetLibXmlVersionLong(void) {
    return PyOS_strtol(xmlParserVersion, NULL, 10);
}

long PyXmlSec_GetLibXmlVersionMajor(void) {
    return XMLSEC_EXTRACT_MAJOR(PyXmlSec_GetLibXmlVersionLong());
}
long PyXmlSec_GetLibXmlVersionMinor(void) {
    return XMLSEC_EXTRACT_MINOR(PyXmlSec_GetLibXmlVersionLong());
}
long PyXmlSec_GetLibXmlVersionPatch(void) {
    return XMLSEC_EXTRACT_PATCH(PyXmlSec_GetLibXmlVersionLong());
}

long PyXmlSec_GetLibXmlCompiledVersionMajor(void) {
    return XMLSEC_EXTRACT_MAJOR(LIBXML_VERSION);
}
long PyXmlSec_GetLibXmlCompiledVersionMinor(void) {
    return XMLSEC_EXTRACT_MINOR(LIBXML_VERSION);
}
long PyXmlSec_GetLibXmlCompiledVersionPatch(void) {
    return XMLSEC_EXTRACT_PATCH(LIBXML_VERSION);
}
