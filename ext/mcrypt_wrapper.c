/*
 * mcrypt_wrapper.c
 *
 * Copyright (c) 2009 Philip Garrett.
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
#include <string.h>
#include <mcrypt.h>

#define RSTR_N(V)       (NIL_P(V) ? NULL : RSTRING(V)->ptr)
#define TO_RB_BOOL(V)   ((V) ? Qtrue : Qfalse)

/* utilities */
static ID    sym_to_s;
static VALUE to_s(VALUE o);

static ID    sym_canonicalize_algorithm;
static VALUE canonicalize_algorithm(VALUE o);

static char *dup_rbstring(VALUE o, int include_null);

static VALUE enumerate_key_sizes(int *sizes, int num_of_sizes, int max_size);

/* globals */
static VALUE cMcrypt;
static VALUE cInvalidAlgorithmOrModeError;
static VALUE cMcryptRuntimeError;
static VALUE mc_alloc(VALUE klass);
static void  mc_free(void *p);

/* instance methods */
static VALUE mc_initialize(int argc, VALUE *argv, VALUE self);
static VALUE mc_generic_init(VALUE self);
static VALUE mc_generic_deinit(VALUE self);
static VALUE mc_encrypt_generic(VALUE self, VALUE plaintext);
static VALUE mc_decrypt_generic(VALUE self, VALUE ciphertext);
static VALUE mc_key_size(VALUE self);
static VALUE mc_block_size(VALUE self);
static VALUE mc_iv_size(VALUE self);
static VALUE mc_is_block_algorithm(VALUE self);
static VALUE mc_is_block_mode(VALUE self);
static VALUE mc_is_block_algorithm_mode(VALUE self);
static VALUE mc_algorithm_version(VALUE self);
static VALUE mc_mode_version(VALUE self);

/* class methods */
static VALUE mck_algorithms(VALUE self);
static VALUE mck_modes(VALUE self);
static VALUE mck_is_block_algorithm(VALUE self, VALUE algo);
static VALUE mck_key_size(VALUE self, VALUE algo);
static VALUE mck_block_size(VALUE self, VALUE algo);
static VALUE mck_is_block_algorithm_mode(VALUE self, VALUE mode);
static VALUE mck_is_block_mode(VALUE self, VALUE mode);
static VALUE mck_algorithm_version(VALUE self, VALUE algo);
static VALUE mck_mode_version(VALUE self, VALUE mode);


/*= IMPLEMENTATION =*/

static VALUE mc_alloc(VALUE klass)
{
  MCRYPT *box;
  box = malloc(sizeof(MCRYPT));
  *box = 0;   /* will populate in mc_initialize */
  return Data_Wrap_Struct(klass, 0, mc_free, box);
}

static void mc_free(void *p)
{
  MCRYPT *box = (MCRYPT *)p;
  if (*box != NULL) {
    mcrypt_generic_deinit(*box);  /* shutdown */
    mcrypt_module_close(*box);    /* free */
  }
  free(box);
}

static VALUE mc_initialize(int argc, VALUE *argv, VALUE self)
{
    VALUE algo, mode, key, iv;
    char *s_algo, *s_mode;
    MCRYPT *box;
    int rv;

    rb_scan_args(argc, argv, "22", &algo, &mode, &key, &iv);

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
        /* MCRYPT_FAILED is currently 0, but we should explicitly set
           to zero in case they change that. We don't want to attempt to
           free it later. */
        *box = 0;
        char message[256];
        snprintf(message, sizeof(message),
                 "Could not initialize using algorithm '%s' with mode "
                 "'%s'.  Check mcrypt(3) for supported combinations.",
                 s_algo, s_mode);
        free(s_algo);
        free(s_mode);
        rb_raise(cInvalidAlgorithmOrModeError, message);
    }
    free(s_algo);
    free(s_mode);

    rb_iv_set(self, "@algorithm", algo);
    rb_iv_set(self, "@mode", mode);

    if (!NIL_P(key))
        rb_funcall(self, rb_intern("after_init"), 2, key, iv);

    return self;
}

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
                             (void *)RSTRING(key)->ptr,
                             RSTRING(key)->len,
                             RSTR_N(iv));
    if (rv < 0) {
        const char *err = mcrypt_strerror(rv);
        rb_raise(cMcryptRuntimeError, "Could not initialize mcrypt: %s", err);
    }

    return Qnil;
}

static VALUE mc_generic_deinit(VALUE self)
{
    MCRYPT *box;
    Data_Get_Struct(self, MCRYPT, box);
    mcrypt_generic_deinit(*box);
    return Qnil;
}

static VALUE mc_encrypt_generic(VALUE self, VALUE plaintext)
{
    /* plaintext is encrypted in-place */
    MCRYPT *box;
    VALUE ciphertext;
    int rv;

    Data_Get_Struct(self, MCRYPT, box);

    /* rb_str_dup doesn't actually copy the buffer, hence rb_str_new */
    ciphertext = rb_str_new(RSTRING(plaintext)->ptr, RSTRING(plaintext)->len);

    rv = mcrypt_generic(*box, (void *)RSTRING(ciphertext)->ptr, RSTRING(ciphertext)->len);
    if (rv != 0)
        rb_raise(cMcryptRuntimeError, "internal error: mcrypt_generic returned %d", rv);
    return ciphertext;
}

static VALUE mc_decrypt_generic(VALUE self, VALUE ciphertext)
{
    /* ciphertext is decrypted in-place */
    MCRYPT *box;
    VALUE plaintext;
    int rv;

    Data_Get_Struct(self, MCRYPT, box);

    /* rb_str_dup doesn't actually copy the buffer, hence rb_str_new */
    plaintext = rb_str_new(RSTRING(ciphertext)->ptr, RSTRING(ciphertext)->len);

    rv = mdecrypt_generic(*box, (void *)RSTRING(plaintext)->ptr, RSTRING(plaintext)->len);
    if (rv != 0)
        rb_raise(cMcryptRuntimeError, "internal error: mdecrypt_generic returned %d", rv);
    return plaintext;
}

static VALUE mc_key_size(VALUE self)
{
    MCRYPT *box;
    Data_Get_Struct(self, MCRYPT, box);
    return INT2FIX(mcrypt_enc_get_key_size(*box));
}

static VALUE mc_block_size(VALUE self)
{
    MCRYPT *box;
    Data_Get_Struct(self, MCRYPT, box);
    return INT2FIX(mcrypt_enc_get_block_size(*box));
}

static VALUE mc_iv_size(VALUE self)
{
    MCRYPT *box;
    Data_Get_Struct(self, MCRYPT, box);
    return INT2FIX(mcrypt_enc_get_iv_size(*box));
}

static VALUE mc_is_block_algorithm(VALUE self)
{
    MCRYPT *box;
    Data_Get_Struct(self, MCRYPT, box);
    return TO_RB_BOOL(mcrypt_enc_is_block_algorithm(*box));
}

static VALUE mc_is_block_mode(VALUE self)
{
    MCRYPT *box;
    Data_Get_Struct(self, MCRYPT, box);
    return TO_RB_BOOL(mcrypt_enc_is_block_mode(*box));
}

static VALUE mc_is_block_algorithm_mode(VALUE self)
{
    MCRYPT *box;
    Data_Get_Struct(self, MCRYPT, box);
    return TO_RB_BOOL(mcrypt_enc_is_block_algorithm_mode(*box));
}

static VALUE mc_mode_has_iv(VALUE self)
{
    MCRYPT *box;
    Data_Get_Struct(self, MCRYPT, box);
    return TO_RB_BOOL(mcrypt_enc_mode_has_iv(*box));
}

static VALUE mc_key_sizes(VALUE self)
{
    VALUE rv;
    MCRYPT *box;
    int *sizes, num_of_sizes;
    Data_Get_Struct(self, MCRYPT, box);

    sizes = mcrypt_enc_get_supported_key_sizes(*box, &num_of_sizes);
    return enumerate_key_sizes(sizes, num_of_sizes, mcrypt_enc_get_key_size(*box));
}

static VALUE mc_algorithm_version(VALUE self)
{
    int version;
    VALUE algo = rb_iv_get(self,"@algorithm");
    version = mcrypt_module_algorithm_version(RSTRING(algo)->ptr, NULL);
    return INT2FIX(version);
}

static VALUE mc_mode_version(VALUE self)
{
    int version;
    VALUE mode = rb_iv_get(self,"@mode");
    version = mcrypt_module_mode_version(RSTRING(mode)->ptr, NULL);
    return INT2FIX(version);
}

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

static VALUE mck_is_block_algorithm(VALUE self, VALUE algo)
{
    algo = canonicalize_algorithm(algo);
    return TO_RB_BOOL(mcrypt_module_is_block_algorithm(RSTRING(algo)->ptr,NULL));
}

static VALUE mck_key_size(VALUE self, VALUE algo)
{
    algo = canonicalize_algorithm(algo);
    return INT2FIX(mcrypt_module_get_algo_key_size(RSTRING(algo)->ptr,NULL));
}

static VALUE mck_block_size(VALUE self, VALUE algo)
{
    algo = canonicalize_algorithm(algo);
    return INT2FIX(mcrypt_module_get_algo_block_size(RSTRING(algo)->ptr,NULL));
}

static VALUE mck_key_sizes(VALUE self, VALUE algo)
{
    int *sizes, num_of_sizes, max;
    algo = canonicalize_algorithm(algo);
    max = mcrypt_module_get_algo_key_size(RSTRING(algo)->ptr, NULL);
    sizes = mcrypt_module_get_algo_supported_key_sizes(RSTRING(algo)->ptr, NULL, &num_of_sizes);
    return enumerate_key_sizes(sizes, num_of_sizes, max);
}

static VALUE mck_is_block_algorithm_mode(VALUE self, VALUE mode)
{
    mode = to_s(mode);
    return TO_RB_BOOL(mcrypt_module_is_block_algorithm_mode(RSTRING(mode)->ptr,NULL));
}

static VALUE mck_is_block_mode(VALUE self, VALUE mode)
{
    mode = to_s(mode);
    return TO_RB_BOOL(mcrypt_module_is_block_mode(RSTRING(mode)->ptr,NULL));
}

static VALUE mck_algorithm_version(VALUE self, VALUE algo)
{
    algo = canonicalize_algorithm(algo);
    return INT2FIX(mcrypt_module_algorithm_version(RSTRING(algo)->ptr, NULL));
}

static VALUE mck_mode_version(VALUE self, VALUE mode)
{
    mode = to_s(mode);
    return INT2FIX(mcrypt_module_mode_version(RSTRING(mode)->ptr, NULL));
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
    rv = malloc(RSTRING(str)->len + (include_null ? 1 : 0));
    memcpy(rv, RSTRING(str)->ptr, RSTRING(str)->len);
    if (include_null)
        rv[RSTRING(str)->len] = '\0';
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
