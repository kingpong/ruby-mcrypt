/*
 * mcrypt_wrapper.c
 *
 * Copyright (c) 2009-2013 Philip Garrett.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be included
 * in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
 * OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 * IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
 * CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
 * TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
 * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

#include "ruby.h"
#include <limits.h>
#include <string.h>
#include <mcrypt.h>

#ifdef RUBY_18
# ifndef RSTRING_PTR
#  define RSTRING_PTR(x) (RSTRING(x)->ptr)
# endif
# ifndef RSTRING_LEN
#  define RSTRING_LEN(x) (RSTRING(x)->len)
# endif
#endif

#define RSTR_N(V)       (NIL_P(V) ? NULL : RSTRING_PTR(V))
#define TO_RB_BOOL(V)   ((V) ? Qtrue : Qfalse)

/* utilities */
static ID    sym_to_s;
static VALUE to_s(VALUE o);

static ID    sym_canonicalize_algorithm;
static VALUE canonicalize_algorithm(VALUE o);

static char *dup_rbstring(VALUE o, int include_null);

static VALUE enumerate_key_sizes(int *sizes, int num_of_sizes, int max_size);

static int safe_len(long orig);

/* globals */
static VALUE cMcrypt;
static VALUE cInvalidAlgorithmOrModeError;
static VALUE cMcryptRuntimeError;


static void mc_free(void *p)
{
  MCRYPT *box = (MCRYPT *)p;
  if (*box != NULL) {
    mcrypt_generic_deinit(*box);  /* shutdown */
    mcrypt_module_close(*box);    /* free */
  }
  free(box);
}

static VALUE mc_alloc(VALUE klass)
{
  MCRYPT *box;
  box = malloc(sizeof(MCRYPT));
  *box = 0;   /* will populate in mc_initialize */
  return Data_Wrap_Struct(klass, 0, mc_free, box);
}


/*
 * call-seq:
 *  Mcrypt.new(algorithm,mode,key=nil,iv=nil,padding=nil) -> new_mcrypt
 *
 * Creates and initializes a new Mcrypt object with the specified +algorithm+ and +mode+.
 * +key+, +iv+ and +padding+ will also be initialized if they are present.
 */
static VALUE mc_initialize(int argc, VALUE *argv, VALUE self)
{
    VALUE algo, mode, key, iv, padding;
    char *s_algo, *s_mode;
    MCRYPT *box;

    rb_scan_args(argc, argv, "23", &algo, &mode, &key, &iv, &padding);

    Data_Get_Struct(self, MCRYPT, box);

    /* sanity check.  should be empty still */
    if (*box != NULL)
        rb_raise(rb_eFatal, "mcrypt binding internal error");

    /* convert :rijndael_256 to "rijndael-256" */
    algo = canonicalize_algorithm(algo);
    mode = to_s(mode);

    /* mcrypt needs null-terminated strings */
    s_algo = dup_rbstring(algo, 1);
    s_mode = dup_rbstring(mode, 1);

    *box = mcrypt_module_open(s_algo, NULL, s_mode, NULL);
    if (*box == MCRYPT_FAILED) {
        char message[256];
        /* MCRYPT_FAILED is currently 0, but we should explicitly set
           to zero in case they change that. We don't want to attempt to
           free it later. */
        *box = 0;
        snprintf(message, sizeof(message),
                 "Could not initialize using algorithm '%s' with mode "
                 "'%s'.  Check mcrypt(3) for supported combinations.",
                 s_algo, s_mode);
        free(s_algo);
        free(s_mode);
        rb_raise(cInvalidAlgorithmOrModeError, message, NULL);
    }
    free(s_algo);
    free(s_mode);

    rb_iv_set(self, "@algorithm", algo);
    rb_iv_set(self, "@mode", mode);
    rb_iv_set(self, "@opened", TO_RB_BOOL(0));

    /* post-initialization stuff that's easier done in ruby */
    rb_funcall(self, rb_intern("after_init"), 3, key, iv, padding);

    return self;
}

/* :nodoc: */
static VALUE mc_generic_init(VALUE self)
{
    /* ruby has already validated @key and @iv */
    VALUE key, iv;
    int rv;
    MCRYPT *box;
    Data_Get_Struct(self, MCRYPT, box);

    key = rb_iv_get(self, "@key");
    iv  = rb_iv_get(self, "@iv");

    rv = mcrypt_generic_init(*box,
                             (void *)RSTRING_PTR(key),
                             safe_len(RSTRING_LEN(key)),
                             RSTR_N(iv));
    if (rv < 0) {
        const char *err = mcrypt_strerror(rv);
        rb_raise(cMcryptRuntimeError, "Could not initialize mcrypt: %s", err);
    }

    return Qnil;
}

/* :nodoc: */
static VALUE mc_generic_deinit(VALUE self)
{
    MCRYPT *box;
    Data_Get_Struct(self, MCRYPT, box);
    mcrypt_generic_deinit(*box);
    return Qnil;
}

/* :nodoc: */
static VALUE mc_encrypt_generic(VALUE self, VALUE plaintext)
{
    /* plaintext is encrypted in-place */
    MCRYPT *box;
    VALUE ciphertext;
    int rv;

    Data_Get_Struct(self, MCRYPT, box);

    /* rb_str_dup doesn't actually copy the buffer, hence rb_str_new */
    ciphertext = rb_str_new(RSTRING_PTR(plaintext), RSTRING_LEN(plaintext));

    rv = mcrypt_generic(*box, (void *)RSTRING_PTR(ciphertext),
                        safe_len(RSTRING_LEN(ciphertext)));
    if (rv != 0)
        rb_raise(cMcryptRuntimeError, "internal error: mcrypt_generic returned %d", rv);
    return ciphertext;
}

/* :nodoc: */
static VALUE mc_decrypt_generic(VALUE self, VALUE ciphertext)
{
    /* ciphertext is decrypted in-place */
    MCRYPT *box;
    VALUE plaintext;
    int rv;

    Data_Get_Struct(self, MCRYPT, box);

    /* rb_str_dup doesn't actually copy the buffer, hence rb_str_new */
    plaintext = rb_str_new(RSTRING_PTR(ciphertext), RSTRING_LEN(ciphertext));

    rv = mdecrypt_generic(*box, (void *)RSTRING_PTR(plaintext),
                          safe_len(RSTRING_LEN(plaintext)));
    if (rv != 0)
        rb_raise(cMcryptRuntimeError, "internal error: mdecrypt_generic returned %d", rv);
    return plaintext;
}

/*
 * call-seq:
 *  key_size -> Fixnum
 *
 * Returns the maximum key size for the algorithm in use.
 */
static VALUE mc_key_size(VALUE self)
{
    MCRYPT *box;
    Data_Get_Struct(self, MCRYPT, box);
    return INT2FIX(mcrypt_enc_get_key_size(*box));
}

/*
 * call-seq:
 *  block_size -> Fixnum
 *
 * Returns the block size (in bytes) for the algorithm in use. If it
 * is a stream algorithm, this will be 1.
 */
static VALUE mc_block_size(VALUE self)
{
    MCRYPT *box;
    Data_Get_Struct(self, MCRYPT, box);
    return INT2FIX(mcrypt_enc_get_block_size(*box));
}

/*
 * call-seq:
 *  iv_size -> Fixnum or nil
 *
 * Returns the IV size (in bytes) for the mode in use. If the mode does
 * not use an IV, returns nil.
 */
static VALUE mc_iv_size(VALUE self)
{
    MCRYPT *box;
    Data_Get_Struct(self, MCRYPT, box);
    if (mcrypt_enc_mode_has_iv(*box))
      return INT2FIX(mcrypt_enc_get_iv_size(*box));
    else
      return Qnil;
}

/*
 * call-seq:
 *  block_algorithm? -> true or false
 *
 * True if the algorithm in use operates in blocks.
 */
static VALUE mc_is_block_algorithm(VALUE self)
{
    MCRYPT *box;
    Data_Get_Struct(self, MCRYPT, box);
    return TO_RB_BOOL(mcrypt_enc_is_block_algorithm(*box));
}

/*
 * call-seq:
 *  block_mode? -> true or false
 *
 * True if the encryption mode in use operates in blocks.
 */
static VALUE mc_is_block_mode(VALUE self)
{
    MCRYPT *box;
    Data_Get_Struct(self, MCRYPT, box);
    return TO_RB_BOOL(mcrypt_enc_is_block_mode(*box));
}

/*
 * call-seq:
 *  block_algorithm_mode? -> true or false
 *
 * True if the encryption mode is for use with block algorithms.
 */
static VALUE mc_is_block_algorithm_mode(VALUE self)
{
    MCRYPT *box;
    Data_Get_Struct(self, MCRYPT, box);
    return TO_RB_BOOL(mcrypt_enc_is_block_algorithm_mode(*box));
}

/*
 * call-seq:
 *  has_iv? -> true or false
 *
 * True if the the encryption mode uses an IV.
 */
static VALUE mc_mode_has_iv(VALUE self)
{
    MCRYPT *box;
    Data_Get_Struct(self, MCRYPT, box);
    return TO_RB_BOOL(mcrypt_enc_mode_has_iv(*box));
}

/*
 * call-seq:
 *  key_sizes -> Array
 *
 * An array of the key sizes supported by the algorithm.
 */
static VALUE mc_key_sizes(VALUE self)
{
    MCRYPT *box;
    int *sizes, num_of_sizes;
    Data_Get_Struct(self, MCRYPT, box);

    sizes = mcrypt_enc_get_supported_key_sizes(*box, &num_of_sizes);
    return enumerate_key_sizes(sizes, num_of_sizes, mcrypt_enc_get_key_size(*box));
}

/*
 * call-seq:
 *  algorithm_version -> Fixnum
 *
 * The numeric version of the algorithm implementation.
 */
static VALUE mc_algorithm_version(VALUE self)
{
    int version;
    VALUE algo = rb_iv_get(self,"@algorithm");
    version = mcrypt_module_algorithm_version(RSTRING_PTR(algo), NULL);
    return INT2FIX(version);
}

/*
 * call-seq:
 *  mode_version -> Fixnum
 *
 * The numeric version of the encryption mode implementation.
 */
static VALUE mc_mode_version(VALUE self)
{
    int version;
    VALUE mode = rb_iv_get(self,"@mode");
    version = mcrypt_module_mode_version(RSTRING_PTR(mode), NULL);
    return INT2FIX(version);
}

/*
 * call-seq:
 *  Mcrypt.algorithms -> Array
 *
 * Returns an array of all the supported algorithm names.
 */
static VALUE mck_algorithms(VALUE self)
{
    VALUE rv;
    int size, i;
    char **list;

    list = mcrypt_list_algorithms(NULL, &size);
    rv = rb_ary_new2(size);
    for (i = 0; i < size; i++) {
        rb_ary_push(rv, rb_str_new2(list[i]));
    }
    mcrypt_free_p(list, size);

    return rv;
}

/*
 * call-seq:
 *  Mcrypt.modes -> Array
 *
 * Returns an array of all the supported mode names.
 */
static VALUE mck_modes(VALUE self)
{
    VALUE rv;
    int size, i;
    char **list;

    list = mcrypt_list_modes(NULL, &size);
    rv = rb_ary_new2(size);
    for (i = 0; i < size; i++) {
        rb_ary_push(rv, rb_str_new2(list[i]));
    }
    mcrypt_free_p(list, size);

    return rv;
}

/*
 * call-seq:
 *  Mcrypt.block_algorithm?(algorithm) -> true or false
 *
 * Returns true if the specified algorithm operates in blocks.
 */
static VALUE mck_is_block_algorithm(VALUE self, VALUE algo)
{
    algo = canonicalize_algorithm(algo);
    return TO_RB_BOOL(mcrypt_module_is_block_algorithm(RSTRING_PTR(algo),NULL));
}

/*
 * call-seq:
 *  Mcrypt.key_size(algorithm) -> Fixnum
 *
 * Returns the maximum key size of the specified algorithm.
 */
static VALUE mck_key_size(VALUE self, VALUE algo)
{
    algo = canonicalize_algorithm(algo);
    return INT2FIX(mcrypt_module_get_algo_key_size(RSTRING_PTR(algo),NULL));
}

/*
 * call-seq:
 *  Mcrypt.block_size(algorithm) -> Fixnum
 *
 * Returns the block size of the specified algorithm.
 */
static VALUE mck_block_size(VALUE self, VALUE algo)
{
    algo = canonicalize_algorithm(algo);
    return INT2FIX(mcrypt_module_get_algo_block_size(RSTRING_PTR(algo),NULL));
}

/*
 * call-seq:
 *  Mcrypt.key_sizes(algorithm) -> Array
 *
 * Returns the key sizes supported by the specified algorithm.
 */
static VALUE mck_key_sizes(VALUE self, VALUE algo)
{
    int *sizes, num_of_sizes, max;
    algo = canonicalize_algorithm(algo);
    max = mcrypt_module_get_algo_key_size(RSTRING_PTR(algo), NULL);
    sizes = mcrypt_module_get_algo_supported_key_sizes(RSTRING_PTR(algo), NULL, &num_of_sizes);
    return enumerate_key_sizes(sizes, num_of_sizes, max);
}

/*
 * call-seq:
 *  Mcrypt.block_algorithm_mode?(mode) -> true or false
 *
 * Returns true if the specified mode is for use with block algorithms.
 */
static VALUE mck_is_block_algorithm_mode(VALUE self, VALUE mode)
{
    mode = to_s(mode);
    return TO_RB_BOOL(mcrypt_module_is_block_algorithm_mode(RSTRING_PTR(mode),NULL));
}

/*
 * call-seq:
 *  Mcrypt.block_mode?(mode) -> true or false
 *
 * Returns true if the specified mode operates in blocks.
 */
static VALUE mck_is_block_mode(VALUE self, VALUE mode)
{
    mode = to_s(mode);
    return TO_RB_BOOL(mcrypt_module_is_block_mode(RSTRING_PTR(mode),NULL));
}

/*
 * call-seq:
 *  Mcrypt.algorithm_version(algorithm) -> Fixnum
 *
 * Returns the implementation version number of the specified algorithm.
 */
static VALUE mck_algorithm_version(VALUE self, VALUE algo)
{
    algo = canonicalize_algorithm(algo);
    return INT2FIX(mcrypt_module_algorithm_version(RSTRING_PTR(algo), NULL));
}

/*
 * call-seq:
 *  Mcrypt.mode_version(mode) -> Fixnum
 *
 * Returns the implementation version number of the specified mode.
 */
static VALUE mck_mode_version(VALUE self, VALUE mode)
{
    mode = to_s(mode);
    return INT2FIX(mcrypt_module_mode_version(RSTRING_PTR(mode), NULL));
}

void Init_mcrypt()
{
    /* look up once, use many */
    sym_to_s = rb_intern("to_s");
    sym_canonicalize_algorithm = rb_intern("canonicalize_algorithm");

    /*= GLOBALS =*/
    cMcrypt = rb_define_class("Mcrypt", rb_cObject);
    cInvalidAlgorithmOrModeError = rb_define_class_under(cMcrypt, "InvalidAlgorithmOrModeError", rb_eArgError);
    cMcryptRuntimeError = rb_define_class_under(cMcrypt, "RuntimeError", rb_eRuntimeError);
    rb_define_const(cMcrypt, "LIBMCRYPT_VERSION", rb_str_new2(LIBMCRYPT_VERSION));
    rb_define_alloc_func(cMcrypt, mc_alloc);

    /*= INSTANCE METHODS =*/
    rb_define_method(cMcrypt, "initialize", mc_initialize, -1);
    rb_define_method(cMcrypt, "generic_init", mc_generic_init, 0);
    rb_define_method(cMcrypt, "generic_deinit", mc_generic_deinit, 0);
    rb_define_method(cMcrypt, "encrypt_generic", mc_encrypt_generic, 1);
    rb_define_method(cMcrypt, "decrypt_generic", mc_decrypt_generic, 1);
    rb_define_method(cMcrypt, "key_size", mc_key_size, 0);
    rb_define_method(cMcrypt, "block_size", mc_block_size, 0);
    rb_define_method(cMcrypt, "iv_size", mc_iv_size, 0);
    rb_define_method(cMcrypt, "block_algorithm?", mc_is_block_algorithm, 0);
    rb_define_method(cMcrypt, "block_mode?", mc_is_block_mode, 0);
    rb_define_method(cMcrypt, "block_algorithm_mode?", mc_is_block_algorithm_mode, 0);
    rb_define_method(cMcrypt, "has_iv?", mc_mode_has_iv, 0);
    rb_define_method(cMcrypt, "key_sizes", mc_key_sizes, 0);
    rb_define_method(cMcrypt, "algorithm_version", mc_algorithm_version, 0);
    rb_define_method(cMcrypt, "mode_version", mc_mode_version, 0);

    /*= CLASS METHODS =*/
    rb_define_singleton_method(cMcrypt, "algorithms", mck_algorithms, 0);
    rb_define_singleton_method(cMcrypt, "modes", mck_modes, 0);
    rb_define_singleton_method(cMcrypt, "block_algorithm?", mck_is_block_algorithm, 1);
    rb_define_singleton_method(cMcrypt, "key_size", mck_key_size, 1);
    rb_define_singleton_method(cMcrypt, "block_size", mck_block_size, 1);
    rb_define_singleton_method(cMcrypt, "key_sizes", mck_key_sizes, 1);
    rb_define_singleton_method(cMcrypt, "block_algorithm_mode?", mck_is_block_algorithm_mode, 1);
    rb_define_singleton_method(cMcrypt, "block_mode?", mck_is_block_mode, 1);
    rb_define_singleton_method(cMcrypt, "algorithm_version", mck_algorithm_version, 1);
    rb_define_singleton_method(cMcrypt, "mode_version", mck_mode_version, 1);

    /* TODO:
       Instance methods:
           (for copying)
           mcrypt_enc_get_state
           mcrypt_enc_set_state
       Maybe:
           self-tests
    */
}


/* UTILITIES */

static VALUE to_s(VALUE o)
{
    return rb_obj_is_kind_of(o,rb_cString)
        ? o : rb_funcall(o, sym_to_s, 0);
}

static VALUE canonicalize_algorithm(VALUE o)
{
    return rb_funcall(cMcrypt, sym_canonicalize_algorithm, 1, o);
}

static char *dup_rbstring(VALUE o, int include_null)
{
    char *rv;
    VALUE str = to_s(o);
    rv = malloc(RSTRING_LEN(str) + (include_null ? 1 : 0));
    memcpy(rv, RSTRING_PTR(str), RSTRING_LEN(str));
    if (include_null)
        rv[RSTRING_LEN(str)] = '\0';
    return rv;
}

static VALUE enumerate_key_sizes(int *sizes, int num_of_sizes, int max_size)
{
    int i;
    VALUE rv;
    if (sizes == NULL && num_of_sizes == 0) {
        rv = rb_ary_new2(max_size);
        for (i = 1; i <= max_size; i++) {
            rb_ary_push(rv, INT2FIX(i));
        }
        return rv;
    }
    else if (num_of_sizes > 0) {
        rv = rb_ary_new2(num_of_sizes);
        for (i = 0; i < num_of_sizes; i++) {
            rb_ary_push(rv, INT2FIX(sizes[i]));
        }
        free(sizes);
        return rv;
    }
    else {
        rb_raise(rb_eFatal, "mcrypt_enc_get_supported_key_sizes returned invalid result.");
        return Qnil;    /* quell warning */
    }
}

static int safe_len(long orig)
{
    int result = (int)orig;
    if (result != orig) {
        rb_raise(cMcryptRuntimeError, "The string is too large. "
                 "This version of mcrypt can only handle %d bytes (32-bit signed int)",
                 INT_MAX);
    }
    return result;
}
