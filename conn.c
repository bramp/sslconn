#include "conn.h"

#include <assert.h>
#include <openssl/err.h>
#include <openssl/ssl.h>

#include "cgo_binding.h"
#include "error.h"
#include "thread.h"
#include "_cgo_export.h"

const int SSLConn_EIO = EIO;
const int SSLConn_EAGAIN = EAGAIN;
const int SSLConn_SSL_ERROR = -10;
const int SSLConn_WANT_READ = -11;
const int SSLConn_WANT_WRITE = -12;
const int SSLConn_ZERO_RETURN = -13;
const int SSLConn_SYSCALL = -14;

void SSLConn_init() {
  SSLConn_init_thread();
  SSL_load_error_strings();
  ERR_load_crypto_strings();
  SSL_library_init();
}

SSLConn *SSLConn_new(SSLConnConfig *config, SSLConnError *err) {
  SSLConn *result;
  SSL_CTX *ctx;
  SSL *ssl;
  BIO *bio;

  // Create new SSL context that understands SSLv2, SSLv3, TLSv1, TLSv1.1 and TLSv1.2 protocols (SSLv23_server_method)
  if (config->is_server) {
    ctx = SSL_CTX_new(SSLv23_server_method());
  } else {
    ctx = SSL_CTX_new(SSLv23_client_method());
  }

  if (!ctx) {
    goto error;
  }

  SSL_CTX_set_verify(ctx, config->verify_mode, NULL); // TODO Set verify callback here
  SSL_CTX_set_options(ctx, config->options);

  if (config->is_server) {
    assert(config->private_key && config->cert);
  }

  if (config->private_key) {
    if (!SSL_CTX_use_PrivateKey(ctx, config->private_key)) {
      goto error;
    }
  }

  if (config->cert) {
    if (!SSL_CTX_use_certificate(ctx, config->cert)) {
      goto error;
    }
  }

  if (config->cipher_list) {
    if (!SSL_CTX_set_cipher_list(ctx, config->cipher_list)) {
      goto error;
    }
  }

  if (config->sess_cache_size >= 0) {
    SSL_CTX_sess_set_cache_size(ctx, config->sess_cache_size);
  }

  if (config->session_id_context) {
    if (!SSL_CTX_set_session_id_context(ctx, config->session_id_context,
                                        strlen(config->session_id_context))) {
      goto error;
    }
  }

  ssl = SSL_new(ctx);
  if (!ssl) {
    goto error;
  }

  SSL_set_mode(ssl, SSL_MODE_ENABLE_PARTIAL_WRITE |
               SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER);

  bio = BIO_new(&goconn_bio_method);
  if (!bio) {
    goto error;
  }

  bio->ptr = config->ptr;
  SSL_set_bio(ssl, bio, bio);

  result = malloc(sizeof(SSLConn));
  result->ssl = ssl;
  result->ctx = ctx;
  result->is_server = config->is_server;

  ERR_remove_state(0);
  return result;

error:
  handle_error(err);
  if (ssl != NULL) SSL_free(ssl);
  if (ctx != NULL) SSL_CTX_free(ctx);
  ERR_remove_state(0);
  return NULL;
}

int SSLConn_read(SSLConn *conn, void *buf, int num, SSLConnError *err) {
  int code, result;

  code = SSL_read(conn->ssl, buf, num);
  return handle_ret_code(conn, err, code);
}

int SSLConn_write(SSLConn *conn, const void *buf, int num, SSLConnError *err) {
  int code, result;

  code = SSL_write(conn->ssl, buf, num);
  return handle_ret_code(conn, err, code);
}

int SSLConn_do_handshake(SSLConn *conn, SSLConnError *err) {
  int code, result;

  if (conn->is_server) {
    code = SSL_accept(conn->ssl);
  } else {
    code = SSL_connect(conn->ssl);
  }

  return handle_ret_code(conn, err, code);
}

int SSLConn_shutdown(SSLConn *conn, SSLConnError *err) {
  int code, result;

  do {
    code = SSL_shutdown(conn->ssl);
  } while (code == 0);

  code = SSL_shutdown(conn->ssl);
  return handle_ret_code(conn, err, code);
}

/**
 * Returns the cipher in use by this connection
 */
SSLCipher * SSLConn_get_cipher(SSLConn *conn) {
  return SSL_get_cipher(conn->ssl);
}

/**
 * Returns all ciphers available on this connection
 * TODO Move into cipher.c
 */
SSLCipher * SSLConn_get_ciphers(SSLConn *conn) {
  int i = 0;
  SSLCipher * last = NULL;
  STACK_OF(SSL_CIPHER) *sk = SSL_get_ciphers(conn->ssl);

  for (i=0; i<sk_SSL_CIPHER_num(sk); i++) {
    SSL_CIPHER *c = sk_SSL_CIPHER_value(sk, i);

    char * buf = malloc(128);

    SSLCipher * result = malloc(sizeof(SSLCipher));
    result->name = SSL_CIPHER_get_name(c);
    result->description = SSL_CIPHER_description(c, buf, 128);
    result->bits = SSL_CIPHER_get_bits(c, &result->alg_bits);
    result->prev = last;

    last = result;
  }

  return last;
}

/**
 * TODO Move into cipher.c
 */
void SSLConn_free_ciphers(SSLCipher *cipher) {
    while(cipher != NULL) {
        SSLCipher *prev = cipher->prev;
        free(cipher->description);
        free(cipher);
        cipher = prev;
    }
}


long goconn_bio_ctrl(BIO *bio, int cmd, long num, void *ptr) {
  if (cmd == BIO_CTRL_FLUSH) {
    return 1;
  }
  return 0;
}

void SSLConn_free(SSLConn *conn) {
  SSL_free(conn->ssl);
  SSL_CTX_free(conn->ctx);
  conn->ssl = NULL;
  conn->ctx = NULL;
  ERR_remove_state(0);
  free(conn);
}

int goconn_bio_create(BIO *bio) {
  bio->init = 1;
  bio->shutdown = 1;
  bio->num = 0;
  bio->ptr = NULL;
  bio->flags = 0;
  return 1;
}

int goconn_bio_destroy(BIO *bio) {
  if (bio == NULL)
    return 0;
  bio->ptr = NULL;
  bio->init = 0;
  bio->flags = 0;
  return 1;
}


int _goconn_bio_write (BIO *bio, const char *buf, int len) {
  struct goconn_bio_write_return ret;
  ret = goconn_bio_write(bio, (char *) buf, len);

  BIO_clear_retry_flags(bio);
  if (ret.r0 == -1 && ret.r1 == EAGAIN) {
    BIO_set_retry_write(bio);
  }

  return ret.r0;
}

int _goconn_bio_read (BIO *bio, char *buf, int len) {
  struct goconn_bio_read_return ret;
  ret = goconn_bio_read(bio, buf, len);

  BIO_clear_retry_flags(bio);
  if (ret.r0 == -1 && ret.r1 == EAGAIN) {
    BIO_set_retry_read(bio);
  }

  return ret.r0;
}

BIO_METHOD goconn_bio_method = {
  ( 200 | 0x400 ),
  "goconn wrapper",
  &_goconn_bio_write,
  &_goconn_bio_read,
  NULL,
  NULL,
  &goconn_bio_ctrl,
  &goconn_bio_create,
  &goconn_bio_destroy,
  NULL
};
