//
// openssl-test.cc
//
// Code adopted from:
// https://zakird.com/2013/10/13/certificate-parsing-with-openssl
// https://wiki.openssl.org/index.php/SSL/TLS_Client
//

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <assert.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <netdb.h>

#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/conf.h>
#include <openssl/x509.h>
#include <openssl/buffer.h>
#include <openssl/x509v3.h>
#include <openssl/opensslconf.h>

#define DEF_HOST_NAME "www.random.org"
#define DEF_HOST_PORT 443
#define DEF_HOST_RESOURCE "/cgi-bin/randbyte?nbytes=32&format=h"

const char *optHostName = DEF_HOST_NAME;
int         optPortNumber = DEF_HOST_PORT;
const char *optResource = DEF_HOST_RESOURCE;

int verify_callback(int preverify, X509_STORE_CTX* x509_ctx);

void init_openssl_library(void);
void print_cn_name(const char* label, X509_NAME* const name);
void print_san_name(const char* label, X509* const cert);
void print_error_string(int lineno, unsigned long err, const char* const label);
const char* get_validation_errstr(long e);
const char *bin2hex(unsigned char *bin, unsigned int len);
const char *time2str(ASN1_TIME *t);

/* Cipher suites, https://www.openssl.org/docs/apps/ciphers.html */
#if 0
const char* const PREFERRED_CIPHERS = "HIGH:!aNULL:!kRSA:!SRP:!PSK:!CAMELLIA:!RC4:!MD5:!DSS";
#elif 0
const char* const PREFERRED_CIPHERS = "kEECDH:kEDH:kRSA:AESGCM:AES256:AES128:3DES:SHA256:SHA84:SHA1:!aNULL:!eNULL:!EXP:!LOW:!MEDIUM!ADH:!AECDH";
#elif 0
const char* const PREFERRED_CIPHERS = NULL;
#elif 1
/* TLS 1.2 only */
const char* PREFERRED_CIPHERS =
	"ECDHE-ECDSA-AES256-GCM-SHA384:"
	"ECDHE-RSA-AES256-GCM-SHA384:"
	"ECDHE-ECDSA-AES128-GCM-SHA256:"
	"ECDHE-RSA-AES128-GCM-SHA256:";
#endif

#if 0
const char* PREFERRED_CIPHERS =

/* TLS 1.2 only */
"ECDHE-ECDSA-AES256-GCM-SHA384:"
"ECDHE-RSA-AES256-GCM-SHA384:"
"ECDHE-ECDSA-AES128-GCM-SHA256:"
"ECDHE-RSA-AES128-GCM-SHA256:"

/* TLS 1.2 only */
"DHE-DSS-AES256-GCM-SHA384:"
"DHE-RSA-AES256-GCM-SHA384:"
"DHE-DSS-AES128-GCM-SHA256:"
"DHE-RSA-AES128-GCM-SHA256:"

/* TLS 1.0 only */
"DHE-DSS-AES256-SHA:"
"DHE-RSA-AES256-SHA:"
"DHE-DSS-AES128-SHA:"
"DHE-RSA-AES128-SHA:"

/* SSL 3.0 and TLS 1.0 */
"EDH-DSS-DES-CBC3-SHA:"
"EDH-RSA-DES-CBC3-SHA:"
"DH-DSS-DES-CBC3-SHA:"
"DH-RSA-DES-CBC3-SHA";
#endif

void usage()
{
	printf("Command line options\n");
	printf("  -h HOST    Set host name.  Default is %s\n", DEF_HOST_NAME);
	printf("  -p PORT    Set port number.  Default is %d\n", DEF_HOST_PORT);
	printf("  -r FILE    Set filename/path/resource.  Default is %s\n", DEF_HOST_RESOURCE);
}

int main(int argc, char* argv[])
{
   for (int i=1; i<argc; i++) {
		if (strcmp(argv[i], "-h") == 0 && i<argc-1) {
			optHostName = argv[++i];
		} else if (strcmp(argv[i], "-p") == 0 && i<argc-1) {
			optPortNumber = atoi(argv[++i]);
		} else if (strcmp(argv[i], "-r") == 0 && i<argc-1) {
			optResource = argv[++i];
		} else {
			usage();
			return 0;
		}
	}

    long res = 1;
    int ret = 1;
    unsigned long ssl_err = 0;

    SSL_CTX* ctx = NULL;
    BIO *web = NULL, *out = NULL;
    SSL *ssl = NULL;

    do {

        /* Internal function that wraps the OpenSSL init's   */
        /* Cannot fail because no OpenSSL function fails ??? */
        init_openssl_library();

        /* https://www.openssl.org/docs/ssl/SSL_CTX_new.html */
        const SSL_METHOD* method = SSLv23_method();
        if (NULL == method) {
				ssl_err = ERR_get_error();
            print_error_string(__LINE__, ssl_err, "SSLv23_method");
            break;
        }

        /* http://www.openssl.org/docs/ssl/ctx_new.html */
        ctx = SSL_CTX_new(method);
        /* ctx = SSL_CTX_new(TLSv1_method()); */
        if (ctx == NULL) {
				ssl_err = ERR_get_error();
            print_error_string(__LINE__, ssl_err, "SSL_CTX_new");
            break;
        }

        /* https://www.openssl.org/docs/ssl/ctx_set_verify.html */
        SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, verify_callback);
        /* Cannot fail */

        /* https://www.openssl.org/docs/ssl/ctx_set_verify.html */
        SSL_CTX_set_verify_depth(ctx, 5);
        /* Cannot fail */

        /* Remove the most egregious. Because SSLv2 and SSLv3 have been      */
        /* removed, a TLSv1.0 handshake is used. The client accepts TLSv1.0  */
        /* and above. An added benefit of TLS 1.0 and above are TLS          */
        /* extensions like Server Name Indicatior (SNI).                     */
        const long flags = SSL_OP_ALL | SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_COMPRESSION;
        long old_opts = SSL_CTX_set_options(ctx, flags);
        (void)(old_opts);

        /* http://www.openssl.org/docs/ssl/SSL_CTX_load_verify_locations.html */
		  const char *pLocalCertFilename = "random-org-chain.pem";
        res = SSL_CTX_load_verify_locations(ctx, pLocalCertFilename, NULL);
        if (1 != res) {
				ssl_err = ERR_get_error();
            /* Non-fatal, but something else will probably break later */
				printf("Unable to open %s\n", pLocalCertFilename);
            print_error_string(__LINE__, ssl_err, "SSL_CTX_load_verify_locations");
            /* break; */
        } else {
				printf("Loaded cert from %s\n", pLocalCertFilename);
		  }

        /* https://www.openssl.org/docs/crypto/BIO_f_ssl.html */
        web = BIO_new_ssl_connect(ctx);
        if (web == NULL) {
				ssl_err = ERR_get_error();
            print_error_string(__LINE__, ssl_err, "BIO_new_ssl_connect");
            break;
        }

        /* https://www.openssl.org/docs/crypto/BIO_s_connect.html */
		  char szHostAndPort[200];
		  sprintf(szHostAndPort, "%s:%d", optHostName, optPortNumber);
		  printf("Connecting to %s\n", szHostAndPort);
        res = BIO_set_conn_hostname(web, szHostAndPort);
        if (1 != res) {
				ssl_err = ERR_get_error();
            print_error_string(__LINE__, ssl_err, "BIO_set_conn_hostname");
            break;
        }

        /* https://www.openssl.org/docs/crypto/BIO_f_ssl.html */
        /* This copies an internal pointer. No need to free.  */
        BIO_get_ssl(web, &ssl);
        if (ssl == NULL) {
				ssl_err = ERR_get_error();
            print_error_string(__LINE__, ssl_err, "BIO_get_ssl");
            break;
        }

        /* https://www.openssl.org/docs/ssl/ssl.html#DEALING_WITH_PROTOCOL_CONTEXTS */
        /* https://www.openssl.org/docs/ssl/SSL_CTX_set_cipher_list.html            */
        res = SSL_set_cipher_list(ssl, PREFERRED_CIPHERS);
        if (1 != res) {
				ssl_err = ERR_get_error();
            print_error_string(__LINE__, ssl_err, "SSL_set_cipher_list");
            break;
        }

        /* No documentation. See the source code for tls.h and s_client.c */
        res = SSL_set_tlsext_host_name(ssl, optHostName);
        if (1 != res) {
				ssl_err = ERR_get_error();
            /* Non-fatal, but who knows what cert might be served by an SNI server  */
            /* (We know its the default site's cert in Apache and IIS...)           */
            print_error_string(__LINE__, ssl_err, "SSL_set_tlsext_host_name");
            /* break; */
        }

        /* https://www.openssl.org/docs/crypto/BIO_s_file.html */
        out = BIO_new_fp(stdout, BIO_NOCLOSE);
        if (NULL == out) {
				ssl_err = ERR_get_error();
            print_error_string(__LINE__, ssl_err, "BIO_new_fp");
            break;
        }

        /* https://www.openssl.org/docs/crypto/BIO_s_connect.html */
		  // verify_callback is called from this function.
        res = BIO_do_connect(web);
        if (1 != res) {
				ssl_err = ERR_get_error();
            print_error_string(__LINE__, ssl_err, "BIO_do_connect");
            break;
        }

        /* https://www.openssl.org/docs/crypto/BIO_f_ssl.html */
        res = BIO_do_handshake(web);
        if (1 != res) {
				ssl_err = ERR_get_error();
            print_error_string(__LINE__, ssl_err, "BIO_do_handshake");
            break;
        }

        /**************************************************************************************/
        /**************************************************************************************/
        /* You need to perform X509 verification here. There are two documents that provide   */
        /*   guidance on the gyrations. First is RFC 5280, and second is RFC 6125. Two other  */
        /*   documents of interest are:                                                       */
        /*     Baseline Certificate Requirements:                                             */
        /*       https://www.cabforum.org/Baseline_Requirements_V1_1_6.pdf                    */
        /*     Extended Validation Certificate Requirements:                                  */
        /*       https://www.cabforum.org/Guidelines_v1_4_3.pdf                               */
        /*                                                                                    */
        /* Here are the minimum steps you should perform:                                     */
        /*   1. Call SSL_get_peer_certificate and ensure the certificate is non-NULL. It      */
        /*      should never be NULL because Anonymous Diffie-Hellman (ADH) is not allowed.   */
        /*   2. Call SSL_get_verify_result and ensure it returns X509_V_OK. This return value */
        /*      depends upon your verify_callback if you provided one. If not, the library    */
        /*      default validation is fine (and you should not need to change it).            */
        /*   3. Verify either the CN or the SAN matches the host you attempted to connect to. */
        /*      Note Well (N.B.): OpenSSL prior to version 1.1.0 did *NOT* perform hostname   */
        /*      verification. If you are using OpenSSL 0.9.8 or 1.0.1, then you will need     */
        /*      to perform hostname verification yourself. The code to get you started on     */
        /*      hostname verification is provided in print_cn_name and print_san_name. Be     */
        /*      sure you are sensitive to ccTLDs (don't navively transform the hostname       */
        /*      string). http://publicsuffix.org/ might be helpful.                           */
        /*                                                                                    */
        /* If all three checks succeed, then you have a chance at a secure connection. But    */
        /*   its only a chance, and you should either pin your certificates (to remove DNS,   */
        /*   CA, and Web Hosters from the equation) or implement a Trust-On-First-Use (TOFU)  */
        /*   scheme like Perspectives or SSH. But before you TOFU, you still have to make     */
        /*   the customary checks to ensure the certifcate passes the sniff test.             */
        /*                                                                                    */
        /* Happy certificate validation hunting!                                              */
        /**************************************************************************************/
        /**************************************************************************************/


        /* Step 1: verify a server certifcate was presented during negotiation */
        /* https://www.openssl.org/docs/ssl/SSL_get_peer_certificate.html          */
        X509* cert = SSL_get_peer_certificate(ssl);
        if (NULL == cert) {
            print_error_string(__LINE__, X509_V_ERR_APPLICATION_VERIFICATION, "SSL_get_peer_certificate");
            break; /* failed */
        }
        X509_free(cert);  /* Free immediately */

        /* Step 2: verify the result of chain verifcation             */
        /* http://www.openssl.org/docs/ssl/SSL_get_verify_result.html */
        /* Error codes: http://www.openssl.org/docs/apps/verify.html  */
        res = SSL_get_verify_result(ssl);
        if (X509_V_OK != res) {
            print_error_string(__LINE__, (unsigned long)res, "SSL_get_verify_results");
//          break; /* failed */
        }

        /* Step 3: hostname verifcation.   */
        /* An exercise left to the reader. */
		  printf("\n");
		  printf("Certificate verification done\n");
		  printf("\n");

        /**************************************************************************************/
        /**************************************************************************************/
        /* Now, we can finally start reading and writing to the BIO...                        */
        /**************************************************************************************/
        /**************************************************************************************/

		  printf("Send GET query to HTTP server\n");
        char szHttpRequest[500];
		  sprintf(szHttpRequest, "GET %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", optResource, optHostName);
        BIO_puts(web, szHttpRequest);
        printf("Fetching: %s from %s\n", optResource, optHostName);

        int len = 0;
        do {
            char buff[1536] = {};

            /* https://www.openssl.org/docs/crypto/BIO_read.html */
            len = BIO_read(web, buff, sizeof(buff));

            if (len > 0) {
					printf("%d bytes read\n", len);
               BIO_write(out, buff, len);
				}

            /* BIO_should_retry returns TRUE unless there's an  */
            /* error. We expect an error when the server        */
            /* provides the response and closes the connection. */

        } while (len > 0 || BIO_should_retry(web));

        ret = 0;

    } while (0);
	 printf("\n");

    if(out)
        BIO_free(out);

    if(web != NULL)
        BIO_free_all(web);

    if(NULL != ctx)
        SSL_CTX_free(ctx);

    return ret;
}

void init_openssl_library(void)
{
    /* https://www.openssl.org/docs/ssl/SSL_library_init.html */
    (void)SSL_library_init();
    /* Cannot fail */

    /* https://www.openssl.org/docs/crypto/ERR_load_crypto_strings.html */
    SSL_load_error_strings();
    /* Cannot fail */

    /* SSL_load_error_strings loads both libssl and libcrypto strings */
    ERR_load_crypto_strings();
    /* Cannot fail */

    /* OpenSSL_config may or may not be called internally, based on */
    /*  some #defines and internal gyrations. Explicitly call it    */
    /*  *IF* you need something from openssl.cfg, such as a         */
    /*  dynamically configured ENGINE.                              */
    OPENSSL_config(NULL);
    /* Cannot fail */

    /* Include <openssl/opensslconf.h> to get this define     */
#if 0 // defined (OPENSSL_THREADS)
    /* TODO TODO TODO TODO TODO TODO TODO TODO TODO TODO TODO */
    /* https://www.openssl.org/docs/crypto/threads.html */
    printf("Warning: thread locking is not implemented\n");
#endif
}

void print_cn_name(const char* label, X509_NAME* const name)
{
    int idx = -1, success = 0;
    unsigned char *utf8 = NULL;

    do {
        if(!name) break; /* failed */

        idx = X509_NAME_get_index_by_NID(name, NID_commonName, -1);
        if(!(idx > -1))  break; /* failed */

        X509_NAME_ENTRY* entry = X509_NAME_get_entry(name, idx);
        if(!entry) break; /* failed */

        ASN1_STRING* data = X509_NAME_ENTRY_get_data(entry);
        if(!data) break; /* failed */

        int length = ASN1_STRING_to_UTF8(&utf8, data);
        if(!utf8 || !(length > 0))  break; /* failed */

        printf("  %s: %s\n", label, utf8);
        success = 1;

    } while (0);

    if (utf8)
        OPENSSL_free(utf8);

    if (!success)
        printf("  %s: <not available>\n", label);
}

void print_san_name(const char* label, X509* const cert)
{
    int success = 0;
    GENERAL_NAMES* names = NULL;
    unsigned char* utf8 = NULL;

    do {
        if (!cert) break; /* failed */

        names = (GENERAL_NAMES*) X509_get_ext_d2i(cert, NID_subject_alt_name, 0, 0);
        if (!names) break;

        int i = 0, count = sk_GENERAL_NAME_num(names);
        if (!count) break; /* failed */

        for ( i = 0; i < count; ++i ) {
            GENERAL_NAME* entry = sk_GENERAL_NAME_value(names, i);
            if (!entry) continue;

            if (GEN_DNS == entry->type) {
                int len1 = 0, len2 = -1;

                len1 = ASN1_STRING_to_UTF8(&utf8, entry->d.dNSName);
                if (utf8) {
                    len2 = (int)strlen((const char*)utf8);
                }

                if (len1 != len2) {
                    printf("  Strlen and ASN1_STRING size do not match (embedded null?): %d vs %d\n", len2, len1);
                }

                /* If there's a problem with string lengths, then     */
                /* we skip the candidate and move on to the next.     */
                /* Another policy would be to fails since it probably */
                /* indicates the client is under attack.              */
                if (utf8 && len1 && len2 && (len1 == len2)) {
                    printf("  %s: %s\n", label, utf8);
                    success = 1;
                }

                if (utf8) {
                    OPENSSL_free(utf8);
						  utf8 = NULL;
                }
            } else {
                printf("  Unknown GENERAL_NAME type: %d\n", entry->type);
            }
        }

    } while (0);

    if (names)
        GENERAL_NAMES_free(names);

    if (utf8)
        OPENSSL_free(utf8);

    if (!success)
        printf("  %s: <not available>\n", label);
}

int verify_callback(int preverify, X509_STORE_CTX* x509_ctx)
{
    /* For error codes, see http://www.openssl.org/docs/apps/verify.html  */

	 printf("\n");
	 printf("Verify cert x509_ctx = %p\n", x509_ctx);
    int depth = X509_STORE_CTX_get_error_depth(x509_ctx);
    int err = X509_STORE_CTX_get_error(x509_ctx);

    X509* cert = X509_STORE_CTX_get_current_cert(x509_ctx);

	 // Fingerprint - SHA-1
	unsigned char fingerprint_buf[512];
	unsigned int fingerprint_len;
	const EVP_MD *digest_sha1 = EVP_sha1();
	int rc1 = X509_digest(cert, digest_sha1, fingerprint_buf, &fingerprint_len);
	if (rc1 != 0) {
		printf("Fingerprint (SHA-1): %s\n", bin2hex(fingerprint_buf, fingerprint_len));
	}
	 // Fingerprint - SHA-256
	const EVP_MD *digest_sha256 = EVP_sha256();
	int rc2 = X509_digest(cert, digest_sha256, fingerprint_buf, &fingerprint_len);
	if (rc2 != 0) {
		printf("Fingerprint (SHA-256): %s\n", bin2hex(fingerprint_buf, fingerprint_len));
	}

	// Serial number
	ASN1_INTEGER *serial = X509_get_serialNumber(cert);
	if (serial != 0) {
		printf("Serial number (hex): %s\n", bin2hex(ASN1_STRING_data(serial), (unsigned int)ASN1_STRING_length(serial)));
		BIGNUM *bn = ASN1_INTEGER_to_BN(serial, NULL);
		if (bn != 0) {
			char *tmp = BN_bn2dec(bn);
			if (tmp != 0) {
				printf("Serial number (dec): %s\n", tmp);
				OPENSSL_free(tmp);
			}
			BN_free(bn);
		}
	}

	// Signature Algorithm
	int pkey_nid = OBJ_obj2nid(cert->cert_info->key->algor->algorithm);
	if (pkey_nid != NID_undef) {
		const char* sslbuf = OBJ_nid2ln(pkey_nid);
		printf("Signature algorithm: %s\n", sslbuf);
	}

	// Validity Period
	ASN1_TIME *not_before = X509_get_notBefore(cert);
	ASN1_TIME *not_after = X509_get_notAfter(cert);
	printf("Valid from: %s\n", time2str(not_before));
	printf("Valid To:   %s\n", time2str(not_after));

    X509_NAME* iname = cert ? X509_get_issuer_name(cert) : NULL;
    X509_NAME* sname = cert ? X509_get_subject_name(cert) : NULL;

    printf("verify_callback depth=%d   preverify=%d\n", depth, preverify);

    /* Issuer is the authority we trust that warrants nothing useful */
    print_cn_name("Issuer (cn)", iname);

    /* Subject is who the certificate is issued to by the authority  */
    print_cn_name("Subject (cn)", sname);

    if (depth == 0) {
        /* If depth is 0, its the server's certificate. Print the SANs */
        print_san_name("Subject (san)", cert);
    }

    if (preverify == 0) {
		  printf("Line:%d:  %s\n", __LINE__, get_validation_errstr(err));
    }

    return 1;
}

void print_error_string(int lineno, unsigned long err, const char* const label)
{
//    const char* const str = ERR_reason_error_string(err);
	 const char * str = get_validation_errstr(err);

    if (str)
        printf("Error(%d): ErrCode:%lu %s: %s\n", lineno, err, label, str);
    else
        printf("Error(%d): %s failed: %lu (0x%lx)\n", lineno, label, err, err);
}


const char *bin2hex(unsigned char *bin, unsigned int len)
{
	static char buffer[1000];
	buffer[0] = 0;
	for (unsigned int i=0; i<len && strlen(buffer) < sizeof(buffer) - 5; i++) {
		sprintf(buffer + strlen(buffer) , "%02x ", bin[i]);
	}
	return buffer;
}

const char *time2str(ASN1_TIME *t)
{
	static char buffer[100];
	if (t == 0)
		return "Null";

	int rc;
	BIO *b = BIO_new(BIO_s_mem());
	rc = ASN1_TIME_print(b, t);
	if (rc <= 0) {
		printf("ASN1_TIME_print failed or wrote no data.\n");
		BIO_free(b);
		return "Error";
	}
	rc = BIO_gets(b, buffer, sizeof(buffer));
	if (rc <= 0) {
		printf("BIO_gets call failed to transfer contents to buf");
		BIO_free(b);
		return "Error";
	}
	BIO_free(b);
	return buffer;
}

const char* get_validation_errstr(long e)
{
	switch ((int) e) {
		case X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT:
			return "ERR_UNABLE_TO_GET_ISSUER_CERT";
		case X509_V_ERR_UNABLE_TO_GET_CRL:
			return "ERR_UNABLE_TO_GET_CRL";
		case X509_V_ERR_UNABLE_TO_DECRYPT_CERT_SIGNATURE:
			return "ERR_UNABLE_TO_DECRYPT_CERT_SIGNATURE";
		case X509_V_ERR_UNABLE_TO_DECRYPT_CRL_SIGNATURE:
			return "ERR_UNABLE_TO_DECRYPT_CRL_SIGNATURE";
		case X509_V_ERR_UNABLE_TO_DECODE_ISSUER_PUBLIC_KEY:
			return "ERR_UNABLE_TO_DECODE_ISSUER_PUBLIC_KEY";
		case X509_V_ERR_CERT_SIGNATURE_FAILURE:
			return "ERR_CERT_SIGNATURE_FAILURE";
		case X509_V_ERR_CRL_SIGNATURE_FAILURE:
			return "ERR_CRL_SIGNATURE_FAILURE";
		case X509_V_ERR_CERT_NOT_YET_VALID:
			return "ERR_CERT_NOT_YET_VALID";
		case X509_V_ERR_CERT_HAS_EXPIRED:
			return "ERR_CERT_HAS_EXPIRED";
		case X509_V_ERR_CRL_NOT_YET_VALID:
			return "ERR_CRL_NOT_YET_VALID";
		case X509_V_ERR_CRL_HAS_EXPIRED:
			return "ERR_CRL_HAS_EXPIRED";
		case X509_V_ERR_ERROR_IN_CERT_NOT_BEFORE_FIELD:
			return "ERR_ERROR_IN_CERT_NOT_BEFORE_FIELD";
		case X509_V_ERR_ERROR_IN_CERT_NOT_AFTER_FIELD:
			return "ERR_ERROR_IN_CERT_NOT_AFTER_FIELD";
		case X509_V_ERR_ERROR_IN_CRL_LAST_UPDATE_FIELD:
			return "ERR_ERROR_IN_CRL_LAST_UPDATE_FIELD";
		case X509_V_ERR_ERROR_IN_CRL_NEXT_UPDATE_FIELD:
			return "ERR_ERROR_IN_CRL_NEXT_UPDATE_FIELD";
		case X509_V_ERR_OUT_OF_MEM:
			return "ERR_OUT_OF_MEM";
		case X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT:
			return "ERR_DEPTH_ZERO_SELF_SIGNED_CERT";
		case X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN:
			return "ERR_SELF_SIGNED_CERT_IN_CHAIN";
		case X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY:
			return "ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY";
		case X509_V_ERR_UNABLE_TO_VERIFY_LEAF_SIGNATURE:
			return "ERR_UNABLE_TO_VERIFY_LEAF_SIGNATURE";
		case X509_V_ERR_CERT_CHAIN_TOO_LONG:
			return "ERR_CERT_CHAIN_TOO_LONG";
		case X509_V_ERR_CERT_REVOKED:
			return "ERR_CERT_REVOKED";
		case X509_V_ERR_INVALID_CA:
			return "ERR_INVALID_CA";
		case X509_V_ERR_PATH_LENGTH_EXCEEDED:
			return "ERR_PATH_LENGTH_EXCEEDED";
		case X509_V_ERR_INVALID_PURPOSE:
			return "ERR_INVALID_PURPOSE";
		case X509_V_ERR_CERT_UNTRUSTED:
			return "ERR_CERT_UNTRUSTED";
		case X509_V_ERR_CERT_REJECTED:
			return "ERR_CERT_REJECTED";
		case X509_V_ERR_SUBJECT_ISSUER_MISMATCH:
			return "ERR_SUBJECT_ISSUER_MISMATCH";
		case X509_V_ERR_AKID_SKID_MISMATCH:
			return "ERR_AKID_SKID_MISMATCH";
		case X509_V_ERR_AKID_ISSUER_SERIAL_MISMATCH:
			return "ERR_AKID_ISSUER_SERIAL_MISMATCH";
		case X509_V_ERR_KEYUSAGE_NO_CERTSIGN:
			return "ERR_KEYUSAGE_NO_CERTSIGN";
		case X509_V_ERR_INVALID_EXTENSION:
			return "ERR_INVALID_EXTENSION";
		case X509_V_ERR_INVALID_POLICY_EXTENSION:
			return "ERR_INVALID_POLICY_EXTENSION";
		case X509_V_ERR_NO_EXPLICIT_POLICY:
			return "ERR_NO_EXPLICIT_POLICY";
		case X509_V_ERR_APPLICATION_VERIFICATION:
			return "ERR_APPLICATION_VERIFICATION";
		default:
			{
				static char text[100];
				sprintf(text, "Unknown error %ld (dec) 0x%04lx (hex)", e, e);
				return text;
			}
	}
}