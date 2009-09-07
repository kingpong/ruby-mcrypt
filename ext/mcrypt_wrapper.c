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

#define RSTR_N(V) (NIL_P(V) ? NULL : RSTRING(V)->ptr)

static ID to_string;
static VALUE to_s(VALUE o);
static char *dup_rbstring(VALUE o, int include_null);

static VALUE cMcrypt;
static VALUE cInvalidAlgorithmOrModeError;

static VALUE mc_alloc(VALUE klass);
static void  mc_free(void *p);

static VALUE mc_alloc(VALUE klass)
{
  MCRYPT *box;
  VALUE obj;

  box = malloc(sizeof(MCRYPT));
  *box = 0;   /* will populate in mc_initialize */
  obj = Data_Wrap_Struct(klass, 0, mc_free, box);

  fprintf(stderr, "Allocated Box\n");
  return obj;
}

static void mc_free(void *p)
{
  MCRYPT *box = (MCRYPT *)p;
  if (*box != NULL) {
    mcrypt_generic_deinit(*box);  /* shutdown */
    mcrypt_module_close(*box);    /* free */
    fprintf(stderr, "Freed Mcrypt\n");
  }
  free(box);
  fprintf(stderr, "Freed Box\n");
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
    fprintf(stderr, "Allocated Mcrypt\n");
    free(s_algo);
    free(s_mode);


    if (!NIL_P(key))
        rb_funcall(self, rb_intern("after_init"), 2, key, iv);

    return self;
}

static VALUE to_s(VALUE o)
{
    return rb_obj_is_kind_of(o,rb_cString)
        ? o : rb_funcall(o, to_string, 0);
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

void Init_mcrypt()
{
    /* look up once, use many */
    to_string = rb_intern("to_s");

    cMcrypt = rb_define_class("Mcrypt", rb_cObject);
    cInvalidAlgorithmOrModeError = rb_define_class_under(cMcrypt, "InvalidAlgorithmOrModeError", rb_eArgError);
    rb_define_const(cMcrypt, "LIBMCRYPT_VERSION", rb_str_new2(LIBMCRYPT_VERSION));
    rb_define_alloc_func(cMcrypt, mc_alloc);
    rb_define_method(cMcrypt, "initialize", mc_initialize, -1);
//    rb_define_method(cMcrypt, "is_block_algorithm", mc_is_block_algorithm, 0);
//    rb_define_method(cMcrypt, "max_key_size", mc_max_key_size, 0);
//    rb_define_method(cMcrypt, "block_size", mc_block_size, 0);
//    rb_define_method(cMcrypt, "algorithm_version", mc_algorithm_version, 0);
}
