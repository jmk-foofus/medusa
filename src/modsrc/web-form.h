#ifndef __MEDUSA_WEB_FORM_H__
#define __MEDUSA_WEB_FORM_H__

#define MODULE_NAME                 "web-form.mod"
#define MODULE_AUTHOR               "Luciano Bello <luciano@linux.org.ar>"
#define MODULE_SUMMARY_USAGE        "Brute force module for web forms"
#define MODULE_VERSION              "3.0"
#define MODULE_SUMMARY_FORMAT       "%s : version %s%s"

#ifdef HAVE_LIBSSL
#define OPENSSL_WARNING             ""
#else
#define OPENSSL_WARNING             " (No usable OPENSSL. Module disabled.)"
#endif

/**
 * MODULE_SUMMARY_USAGE, MODULE_VERSION and, OPENSSL_WARNING have a statically
 * known length.
 * MODULE_SUMMARY_FORMAT has three unbouded string formatting characters
 *
 * snprintf formats those strings to be the former three
 * so the length is
 *  MODULE_SUMMARY_FORMAT - 3 * 2 (for the %s)
 *    + MODULE_SUMMARY_USAGE
 *    + MODULE_VERSION
 *    + OPENSSL_WARNING
 *    + 1 (for the '\0')
 */
#define ILENGTH (size_t) sizeof(MODULE_SUMMARY_FORMAT MODULE_SUMMARY_USAGE MODULE_VERSION OPENSSL_WARNING) - 3 * 2 + 1

#define HTTP_PORT   80
#define HTTPS_PORT 443

#define MODULE_DEFAULT_USER_AGENT   "I'm not Mozilla, I'm Ming Mong"
#define MODULE_DEFAULT_DENY_SIGNAL  "Login incorrect."
#define MODULE_DEFAULT_USERNAME_KEY "username="
#define MODULE_DEFAULT_PASSWORD_KEY "password="
#define MODULE_DEFAULT_FORM_TYPE    FORM_POST

#define GET_STR  "GET"
#define POST_STR "POST"

#if MODULE_DEFAULT_FORM_TYPE == FORM_POST
#define MODULE_DEFAULT_FORM_TYPE_STR POST_STR
#else
#define MODULE_DEFAULT_FORM_TYPE_STR GET_STR
#endif

/**
 * Standard GET request format string. Parameters are:
 *
 *  1. %s, Resource to request
 *  2. %s, Get parameter string
 *  3. %s, Host header
 *  4. %s, User-agent header
 *  5. %s, A custom header
 *  6. %s, Cookies
 */
#define GET_REQUEST_FMT_STR \
  "GET %s%s HTTP/1.1\r\n" \
  "Host: %s\r\n" \
  "User-Agent: %s\r\n" \
  "Connection: close\r\n" \
  "%s" \
  "%s" \
  "\r\n"

/**
 * Standard POST request format string. Parameters are:
 *
 *  1. %s, resource to request
 *  2. %s, host header
 *  3. %s, user-agent header
 *  4. %s, A custom header
 *  5. %s, Cookies
 *  6. %s, Content length
 *  7. %s, POST body
 */
#define POST_REQUEST_FMT_STR \
  "POST %s HTTP/1.1\r\n" \
  "Host: %s\r\n" \
  "User-Agent: %s\r\n" \
  "Connection: close\r\n" \
  "%s" \
  "%s" \
  "Content-Type: application/x-www-form-urlencoded\r\n" \
  "Content-Length: %i\r\n" \
  "\r\n" \
  "%s"

#define COOKIE_HEADER "Cookie: "
#define COOKIE_HEADER_LENGTH sizeof(COOKIE_HEADER)
#define CRLF "\r\n"
#define CRLF_LENGTH sizeof(CRLF)


// Macro definitions which improve code readability

// Inclusive range condition check: lo <= x <= hi
#define BETWEEN(LO,X,HI) ((LO) <= (X) && (X) <= (HI))

// Allocating char buffers of a certain length, this is common
#define charcalloc(n) (char *) calloc(n, sizeof(char))

// Bounded comparison of a string X to a constant string Y
#define EQ_TO_STR_CONST(X,Y) !strncmp((X), (Y), sizeof(Y))

/**
 * Helper macro for setting default string value key-value pairs if command
 * line arguments have not been set. Note that these should only be used on
 * ModuleDataT, because the freeModuleData() on the struct will also free the
 * content. If this is ussed anywhere else, then the programmer is responsible
 * for freeing the memory.
 */

#define _setDefaultOption(dst, value)  \
  *dst = charcalloc(sizeof(value)); \
  snprintf(*dst, sizeof(value) / sizeof(*value), "%s", value)

#ifdef HAVE_LIBSSL

typedef enum FormType {
    FORM_UNKNOWN
  , FORM_GET
  , FORM_POST
} FormTypeT;

typedef struct ModuleData {
  FormTypeT formType;
  char * resourcePath;     // The path to the resource to which we send the login request
  char * resourcePathOld;  // 
  char * hostHeader;       // Host: header value
  char * userAgentHeader;  // User-Agent: header value
  char * denySignal;       // String on which to _fail_ a login
  char * formData;         //
  char * formRest;         // Other form parameters irrelevant for brute force login
  char * formUserKey;      // String for the username key value of the form
  char * formPassKey;      // String for the password key value of the form
  char * customHeaders;    // Custom headers
  char * cookieJar;        // Custom headers
  int nCustomHeaders;      // Number of custom headers
  int changedRequestType;
} ModuleDataT;

// Tells us whether we are to continue processing or not
typedef enum ModuleState {
  MSTATE_INITIALIZE,
  MSTATE_NEW,
  MSTATE_RUNNING,
  MSTATE_EXITING,
  MSTATE_COMPLETE
} ModuleStateT;

// Incomplete list of HTTP status codes
typedef enum HttpStatusCode {
    HTTP_STATUS_PARSE_ERR   = -1  
  , HTTP_STATUS_NOT_IMPL    = -2  

  // Group 2xx
  , HTTP_OK                 = 200

  // Group 3xx
  , HTTP_MOVED_PERMANENTLY  = 301
  , HTTP_FOUND              = 302
  , HTTP_TEMPORARY_REDIRECT = 307
  , HTTP_PERMANENT_REDIRECT = 308

  // Group 4xx
  , HTTP_BAD_REQUEST        = 400
  , HTTP_UNAUTHORIZED       = 401
  , HTTP_FORBIDDEN          = 403
  , HTTP_NOT_FOUND          = 404

} HttpStatusCodeT;

/**
 * Collection of values that reflect the different kinds of path we can deal
 * with.
 */
typedef enum PathType {
  PATHTYPE_UNKNOWN,
  PATHTYPE_URI,
  PATHTYPE_RELATIVE,
  PATHTYPE_ABSOLUTE
} PathTypeT;

int getParamNumber();
int go(sLogin* logins, int argc, char * argv[]);
int initModule(ModuleDataT * _moduleData, sLogin * _psLogin);

#define URL_ENCODE_BYTE_FMT "%%%02x"
static char * urlencodeup(char * szStr) {

int prepareRequestParamString(char ** dst, ModuleDataT * _moduleData, char * szLogin, char * szPassword) {
int prepareRequestString(char ** dst, ModuleDataT * _moduleData, char * szLogin, char * szPassword) {
//static int _sendRequest(int hSocket, ModuleDataT* _moduleData, char* szLogin, char* szPassword) {
//static inline void _setPasswordHelper(sLogin ** login, char * password, int result) {
//static int _request(int hSocket, ModuleDataT * _moduleData, sLogin ** login, char * szLogin, char ** pReceiveBuffer, int * nReceiveBufferSize, char * szPassword) {
//static PathTypeT _pathType(char * path) {
void _resolveLocationPath(char * newLocation, ModuleDataT * _moduleData) {
void _setCookiesFromResponse(ModuleDataT * _moduleData, char * response) {
int tryLogin(int hSocket, ModuleDataT* _moduleData, sLogin** login, char* szLogin, char* szPassword) {


#else // HAVE_LIBSSL

int go(/*@unused@*/ sLogin* logins, /*@unused@*/ int argc, /*@unused@*/ char *argv[]);

#endif // HAVE_LIBSSL

void showUsage();
void summaryUsage(char ** ppszSummary);

#endif //__MEDUSA_WEB_FORM_H__
