/* A Bison parser, made by GNU Bison 3.7.5.  */

/* Bison implementation for Yacc-like parsers in C

   Copyright (C) 1984, 1989-1990, 2000-2015, 2018-2021 Free Software Foundation,
   Inc.

   This program is free software: you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation, either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.  */

/* As a special exception, you may create a larger work that contains
   part or all of the Bison parser skeleton and distribute that work
   under terms of your choice, so long as that work isn't itself a
   parser generator using the skeleton or a modified version thereof
   as a parser skeleton.  Alternatively, if you modify or redistribute
   the parser skeleton itself, you may (at your option) remove this
   special exception, which will cause the skeleton and the resulting
   Bison output files to be licensed under the GNU General Public
   License without this special exception.

   This special exception was added by the Free Software Foundation in
   version 2.2 of Bison.  */

/* C LALR(1) parser skeleton written by Richard Stallman, by
   simplifying the original so-called "semantic" parser.  */

/* DO NOT RELY ON FEATURES THAT ARE NOT DOCUMENTED in the manual,
   especially those whose name start with YY_ or yy_.  They are
   private implementation details that can be changed or removed.  */

/* All symbols defined below should begin with yy or YY, to avoid
   infringing on user name space.  This should be done even for local
   variables, as they might otherwise be expanded by user macros.
   There are some unavoidable exceptions within include files to
   define necessary library symbols; they are noted "INFRINGES ON
   USER NAME SPACE" below.  */

/* Identify Bison output, and Bison version.  */
#define YYBISON 30705

/* Bison version string.  */
#define YYBISON_VERSION "3.7.5"

/* Skeleton name.  */
#define YYSKELETON_NAME "yacc.c"

/* Pure parsers.  */
#define YYPURE 2

/* Push parsers.  */
#define YYPUSH 0

/* Pull parsers.  */
#define YYPULL 1

/* Substitute the type names.  */
#define YYSTYPE         INI_STYPE
/* Substitute the variable and function names.  */
#define yyparse         ini_parse
#define yylex           ini_lex
#define yyerror         ini_error
#define yydebug         ini_debug
#define yynerrs         ini_nerrs

/* First part of user prologue.  */
#line 2 "/home/smamran09/php-src/Zend/zend_ini_parser.y"

/*
   +----------------------------------------------------------------------+
   | Zend Engine                                                          |
   +----------------------------------------------------------------------+
   | Copyright (c) Zend Technologies Ltd. (http://www.zend.com)           |
   +----------------------------------------------------------------------+
   | This source file is subject to version 2.00 of the Zend license,     |
   | that is bundled with this package in the file LICENSE, and is        |
   | available through the world-wide-web at the following url:           |
   | http://www.zend.com/license/2_00.txt.                                |
   | If you did not receive a copy of the Zend license and are unable to  |
   | obtain it through the world-wide-web, please send a note to          |
   | license@zend.com so we can mail you a copy immediately.              |
   +----------------------------------------------------------------------+
   | Authors: Zeev Suraski <zeev@php.net>                                 |
   |          Jani Taskinen <jani@php.net>                                |
   +----------------------------------------------------------------------+
*/

#define DEBUG_CFG_PARSER 0

#include "zend.h"
#include "zend_API.h"
#include "zend_ini.h"
#include "zend_constants.h"
#include "zend_ini_scanner.h"
#include "zend_extensions.h"

#ifdef ZEND_WIN32
#include "win32/syslog.h"
#endif

int ini_parse(void);

#define ZEND_INI_PARSER_CB	(CG(ini_parser_param))->ini_parser_cb
#define ZEND_INI_PARSER_ARG	(CG(ini_parser_param))->arg

#ifdef _MSC_VER
#define YYMALLOC malloc
#define YYFREE free
#endif

#define ZEND_SYSTEM_INI CG(ini_parser_unbuffered_errors)
#define INI_ZVAL_IS_NUMBER 1

static int get_int_val(zval *op) {
	switch (Z_TYPE_P(op)) {
		case IS_LONG:
			return Z_LVAL_P(op);
		case IS_DOUBLE:
			return (int)Z_DVAL_P(op);
		case IS_STRING:
		{
			int val = atoi(Z_STRVAL_P(op));
			zend_string_free(Z_STR_P(op));
			return val;
		}
		EMPTY_SWITCH_DEFAULT_CASE()
	}
}

/* {{{ zend_ini_do_op() */
static void zend_ini_do_op(char type, zval *result, zval *op1, zval *op2)
{
	int i_result;
	int i_op1, i_op2;
	int str_len;
	char str_result[MAX_LENGTH_OF_LONG+1];

	i_op1 = get_int_val(op1);
	i_op2 = op2 ? get_int_val(op2) : 0;

	switch (type) {
		case '|':
			i_result = i_op1 | i_op2;
			break;
		case '&':
			i_result = i_op1 & i_op2;
			break;
		case '^':
			i_result = i_op1 ^ i_op2;
			break;
		case '~':
			i_result = ~i_op1;
			break;
		case '!':
			i_result = !i_op1;
			break;
		default:
			i_result = 0;
			break;
	}

	if (INI_SCNG(scanner_mode) != ZEND_INI_SCANNER_TYPED) {
		str_len = sprintf(str_result, "%d", i_result);
		ZVAL_NEW_STR(result, zend_string_init(str_result, str_len, ZEND_SYSTEM_INI));
	} else {
		ZVAL_LONG(result, i_result);
	}
}
/* }}} */

/* {{{ zend_ini_init_string() */
static void zend_ini_init_string(zval *result)
{
	if (ZEND_SYSTEM_INI) {
		ZVAL_EMPTY_PSTRING(result);
	} else {
		ZVAL_EMPTY_STRING(result);
	}
	Z_EXTRA_P(result) = 0;
}
/* }}} */

/* {{{ zend_ini_add_string() */
static void zend_ini_add_string(zval *result, zval *op1, zval *op2)
{
	int length, op1_len;

	if (Z_TYPE_P(op1) != IS_STRING) {
		/* ZEND_ASSERT(!Z_REFCOUNTED_P(op1)); */
		if (ZEND_SYSTEM_INI) {
			zend_string *tmp_str;
			zend_string *str = zval_get_tmp_string(op1, &tmp_str);
			ZVAL_PSTRINGL(op1, ZSTR_VAL(str), ZSTR_LEN(str));
			zend_tmp_string_release(tmp_str);
		} else {
			ZVAL_STR(op1, zval_get_string_func(op1));
		}
	}
	op1_len = (int)Z_STRLEN_P(op1);

	if (Z_TYPE_P(op2) != IS_STRING) {
		convert_to_string(op2);
	}
	length = op1_len + (int)Z_STRLEN_P(op2);

	ZVAL_NEW_STR(result, zend_string_extend(Z_STR_P(op1), length, ZEND_SYSTEM_INI));
	memcpy(Z_STRVAL_P(result) + op1_len, Z_STRVAL_P(op2), Z_STRLEN_P(op2) + 1);
}
/* }}} */

/* {{{ zend_ini_get_constant() */
static void zend_ini_get_constant(zval *result, zval *name)
{
	zval *c, tmp;

	/* If name contains ':' it is not a constant. Bug #26893. */
	if (!memchr(Z_STRVAL_P(name), ':', Z_STRLEN_P(name))
		   	&& (c = zend_get_constant(Z_STR_P(name))) != 0) {
		if (Z_TYPE_P(c) != IS_STRING) {
			ZVAL_COPY_OR_DUP(&tmp, c);
			if (Z_OPT_CONSTANT(tmp)) {
				zval_update_constant_ex(&tmp, NULL);
			}
			convert_to_string(&tmp);
			c = &tmp;
		}
		ZVAL_NEW_STR(result, zend_string_init(Z_STRVAL_P(c), Z_STRLEN_P(c), ZEND_SYSTEM_INI));
		if (c == &tmp) {
			zend_string_release(Z_STR(tmp));
		}
		zend_string_free(Z_STR_P(name));
	} else {
		*result = *name;
	}
}
/* }}} */

/* {{{ zend_ini_get_var() */
static void zend_ini_get_var(zval *result, zval *name, zval *fallback)
{
	zval *curval;
	char *envvar;

	/* Fetch configuration option value */
	if ((curval = zend_get_configuration_directive(Z_STR_P(name))) != NULL) {
		ZVAL_NEW_STR(result, zend_string_init(Z_STRVAL_P(curval), Z_STRLEN_P(curval), ZEND_SYSTEM_INI));
	/* ..or if not found, try ENV */
	} else if ((envvar = zend_getenv(Z_STRVAL_P(name), Z_STRLEN_P(name))) != NULL ||
			   (envvar = getenv(Z_STRVAL_P(name))) != NULL) {
		ZVAL_NEW_STR(result, zend_string_init(envvar, strlen(envvar), ZEND_SYSTEM_INI));
	/* ..or if not defined, try fallback value */
	} else if (fallback) {
		ZVAL_NEW_STR(result, zend_string_init(Z_STRVAL_P(fallback), strlen(Z_STRVAL_P(fallback)), ZEND_SYSTEM_INI));
	} else {
		zend_ini_init_string(result);
	}

}
/* }}} */

/* {{{ ini_error() */
static ZEND_COLD void ini_error(const char *msg)
{
	char *error_buf;
	int error_buf_len;

	const char *const currently_parsed_filename = zend_ini_scanner_get_filename();
	if (currently_parsed_filename) {
		error_buf_len = 128 + (int)strlen(msg) + (int)strlen(currently_parsed_filename); /* should be more than enough */
		error_buf = (char *) emalloc(error_buf_len);

		sprintf(error_buf, "%s in %s on line %d\n", msg, currently_parsed_filename, zend_ini_scanner_get_lineno());
	} else {
		error_buf = estrdup("Invalid configuration directive\n");
	}

	if (CG(ini_parser_unbuffered_errors)) {
#ifdef ZEND_WIN32
		syslog(LOG_ALERT, "PHP: %s (%s)", error_buf, GetCommandLine());
#endif
		fprintf(stderr, "PHP:  %s", error_buf);
	} else {
		zend_error(E_WARNING, "%s", error_buf);
	}
	efree(error_buf);
}
/* }}} */

/* {{{ zend_parse_ini_file() */
ZEND_API zend_result zend_parse_ini_file(zend_file_handle *fh, bool unbuffered_errors, int scanner_mode, zend_ini_parser_cb_t ini_parser_cb, void *arg)
{
	int retval;
	zend_ini_parser_param ini_parser_param;

	ini_parser_param.ini_parser_cb = ini_parser_cb;
	ini_parser_param.arg = arg;
	CG(ini_parser_param) = &ini_parser_param;

	if (zend_ini_open_file_for_scanning(fh, scanner_mode) == FAILURE) {
		return FAILURE;
	}

	CG(ini_parser_unbuffered_errors) = unbuffered_errors;
	retval = ini_parse();

	shutdown_ini_scanner();

	if (retval == 0) {
		return SUCCESS;
	} else {
		return FAILURE;
	}
}
/* }}} */

/* {{{ zend_parse_ini_string() */
ZEND_API zend_result zend_parse_ini_string(const char *str, bool unbuffered_errors, int scanner_mode, zend_ini_parser_cb_t ini_parser_cb, void *arg)
{
	int retval;
	zend_ini_parser_param ini_parser_param;

	ini_parser_param.ini_parser_cb = ini_parser_cb;
	ini_parser_param.arg = arg;
	CG(ini_parser_param) = &ini_parser_param;

	if (zend_ini_prepare_string_for_scanning(str, scanner_mode) == FAILURE) {
		return FAILURE;
	}

	CG(ini_parser_unbuffered_errors) = unbuffered_errors;
	retval = ini_parse();

	shutdown_ini_scanner();

	if (retval == 0) {
		return SUCCESS;
	} else {
		return FAILURE;
	}
}
/* }}} */

/* {{{ zval_ini_dtor() */
static void zval_ini_dtor(zval *zv)
{
	if (Z_TYPE_P(zv) == IS_STRING) {
		if (ZEND_SYSTEM_INI) {
			GC_MAKE_PERSISTENT_LOCAL(Z_STR_P(zv));
		}
		zend_string_release(Z_STR_P(zv));
	}
}
/* }}} */

static inline zend_result convert_to_number(zval *retval, const char *str, const int str_len)
{
	uint8_t type;
	int overflow;
	zend_long lval;
	double dval;

	if ((type = is_numeric_string_ex(str, str_len, &lval, &dval, 0, &overflow, NULL)) != 0) {
		if (type == IS_LONG) {
			ZVAL_LONG(retval, lval);
			return SUCCESS;
		} else if (type == IS_DOUBLE && !overflow) {
			ZVAL_DOUBLE(retval, dval);
			return SUCCESS;
		}
	}

	return FAILURE;
}

static void normalize_value(zval *zv)
{
	if (INI_SCNG(scanner_mode) != ZEND_INI_SCANNER_TYPED) {
		return;
	}

	ZEND_ASSERT(Z_EXTRA_P(zv) == 0 || Z_EXTRA_P(zv) == INI_ZVAL_IS_NUMBER);
	if (Z_EXTRA_P(zv) == INI_ZVAL_IS_NUMBER && Z_TYPE_P(zv) == IS_STRING) {
		zval number_rv;
		if (convert_to_number(&number_rv, Z_STRVAL_P(zv), Z_STRLEN_P(zv)) == SUCCESS) {
			zval_ptr_dtor(zv);
			ZVAL_COPY_VALUE(zv, &number_rv);
		}
	}
}


#line 402 "/home/smamran09/php-src/Zend/zend_ini_parser.c"

# ifndef YY_CAST
#  ifdef __cplusplus
#   define YY_CAST(Type, Val) static_cast<Type> (Val)
#   define YY_REINTERPRET_CAST(Type, Val) reinterpret_cast<Type> (Val)
#  else
#   define YY_CAST(Type, Val) ((Type) (Val))
#   define YY_REINTERPRET_CAST(Type, Val) ((Type) (Val))
#  endif
# endif
# ifndef YY_NULLPTR
#  if defined __cplusplus
#   if 201103L <= __cplusplus
#    define YY_NULLPTR nullptr
#   else
#    define YY_NULLPTR 0
#   endif
#  else
#   define YY_NULLPTR ((void*)0)
#  endif
# endif

#include "zend_ini_parser.h"
/* Symbol kind.  */
enum yysymbol_kind_t
{
  YYSYMBOL_YYEMPTY = -2,
  YYSYMBOL_YYEOF = 0,                      /* "end of file"  */
  YYSYMBOL_YYerror = 1,                    /* error  */
  YYSYMBOL_YYUNDEF = 2,                    /* "invalid token"  */
  YYSYMBOL_TC_SECTION = 3,                 /* TC_SECTION  */
  YYSYMBOL_TC_RAW = 4,                     /* TC_RAW  */
  YYSYMBOL_TC_CONSTANT = 5,                /* TC_CONSTANT  */
  YYSYMBOL_TC_NUMBER = 6,                  /* TC_NUMBER  */
  YYSYMBOL_TC_STRING = 7,                  /* TC_STRING  */
  YYSYMBOL_TC_WHITESPACE = 8,              /* TC_WHITESPACE  */
  YYSYMBOL_TC_LABEL = 9,                   /* TC_LABEL  */
  YYSYMBOL_TC_OFFSET = 10,                 /* TC_OFFSET  */
  YYSYMBOL_TC_DOLLAR_CURLY = 11,           /* TC_DOLLAR_CURLY  */
  YYSYMBOL_TC_VARNAME = 12,                /* TC_VARNAME  */
  YYSYMBOL_TC_QUOTED_STRING = 13,          /* TC_QUOTED_STRING  */
  YYSYMBOL_TC_FALLBACK = 14,               /* TC_FALLBACK  */
  YYSYMBOL_BOOL_TRUE = 15,                 /* BOOL_TRUE  */
  YYSYMBOL_BOOL_FALSE = 16,                /* BOOL_FALSE  */
  YYSYMBOL_NULL_NULL = 17,                 /* NULL_NULL  */
  YYSYMBOL_END_OF_LINE = 18,               /* END_OF_LINE  */
  YYSYMBOL_19_ = 19,                       /* '='  */
  YYSYMBOL_20_ = 20,                       /* ':'  */
  YYSYMBOL_21_ = 21,                       /* ','  */
  YYSYMBOL_22_ = 22,                       /* '.'  */
  YYSYMBOL_23_ = 23,                       /* '"'  */
  YYSYMBOL_24_ = 24,                       /* '\''  */
  YYSYMBOL_25_ = 25,                       /* '^'  */
  YYSYMBOL_26_ = 26,                       /* '+'  */
  YYSYMBOL_27_ = 27,                       /* '-'  */
  YYSYMBOL_28_ = 28,                       /* '/'  */
  YYSYMBOL_29_ = 29,                       /* '*'  */
  YYSYMBOL_30_ = 30,                       /* '%'  */
  YYSYMBOL_31_ = 31,                       /* '$'  */
  YYSYMBOL_32_ = 32,                       /* '~'  */
  YYSYMBOL_33_ = 33,                       /* '<'  */
  YYSYMBOL_34_ = 34,                       /* '>'  */
  YYSYMBOL_35_ = 35,                       /* '?'  */
  YYSYMBOL_36_ = 36,                       /* '@'  */
  YYSYMBOL_37_ = 37,                       /* '{'  */
  YYSYMBOL_38_ = 38,                       /* '}'  */
  YYSYMBOL_39_ = 39,                       /* '|'  */
  YYSYMBOL_40_ = 40,                       /* '&'  */
  YYSYMBOL_41_ = 41,                       /* '!'  */
  YYSYMBOL_42_ = 42,                       /* ']'  */
  YYSYMBOL_43_ = 43,                       /* '('  */
  YYSYMBOL_44_ = 44,                       /* ')'  */
  YYSYMBOL_YYACCEPT = 45,                  /* $accept  */
  YYSYMBOL_statement_list = 46,            /* statement_list  */
  YYSYMBOL_statement = 47,                 /* statement  */
  YYSYMBOL_section_string_or_value = 48,   /* section_string_or_value  */
  YYSYMBOL_string_or_value = 49,           /* string_or_value  */
  YYSYMBOL_option_offset = 50,             /* option_offset  */
  YYSYMBOL_encapsed_list = 51,             /* encapsed_list  */
  YYSYMBOL_var_string_list_section = 52,   /* var_string_list_section  */
  YYSYMBOL_var_string_list = 53,           /* var_string_list  */
  YYSYMBOL_expr = 54,                      /* expr  */
  YYSYMBOL_cfg_var_ref = 55,               /* cfg_var_ref  */
  YYSYMBOL_fallback = 56,                  /* fallback  */
  YYSYMBOL_constant_literal = 57,          /* constant_literal  */
  YYSYMBOL_constant_string = 58            /* constant_string  */
};
typedef enum yysymbol_kind_t yysymbol_kind_t;




#ifdef short
# undef short
#endif

/* On compilers that do not define __PTRDIFF_MAX__ etc., make sure
   <limits.h> and (if available) <stdint.h> are included
   so that the code can choose integer types of a good width.  */

#ifndef __PTRDIFF_MAX__
# include <limits.h> /* INFRINGES ON USER NAME SPACE */
# if defined __STDC_VERSION__ && 199901 <= __STDC_VERSION__
#  include <stdint.h> /* INFRINGES ON USER NAME SPACE */
#  define YY_STDINT_H
# endif
#endif

/* Narrow types that promote to a signed type and that can represent a
   signed or unsigned integer of at least N bits.  In tables they can
   save space and decrease cache pressure.  Promoting to a signed type
   helps avoid bugs in integer arithmetic.  */

#ifdef __INT_LEAST8_MAX__
typedef __INT_LEAST8_TYPE__ yytype_int8;
#elif defined YY_STDINT_H
typedef int_least8_t yytype_int8;
#else
typedef signed char yytype_int8;
#endif

#ifdef __INT_LEAST16_MAX__
typedef __INT_LEAST16_TYPE__ yytype_int16;
#elif defined YY_STDINT_H
typedef int_least16_t yytype_int16;
#else
typedef short yytype_int16;
#endif

/* Work around bug in HP-UX 11.23, which defines these macros
   incorrectly for preprocessor constants.  This workaround can likely
   be removed in 2023, as HPE has promised support for HP-UX 11.23
   (aka HP-UX 11i v2) only through the end of 2022; see Table 2 of
   <https://h20195.www2.hpe.com/V2/getpdf.aspx/4AA4-7673ENW.pdf>.  */
#ifdef __hpux
# undef UINT_LEAST8_MAX
# undef UINT_LEAST16_MAX
# define UINT_LEAST8_MAX 255
# define UINT_LEAST16_MAX 65535
#endif

#if defined __UINT_LEAST8_MAX__ && __UINT_LEAST8_MAX__ <= __INT_MAX__
typedef __UINT_LEAST8_TYPE__ yytype_uint8;
#elif (!defined __UINT_LEAST8_MAX__ && defined YY_STDINT_H \
       && UINT_LEAST8_MAX <= INT_MAX)
typedef uint_least8_t yytype_uint8;
#elif !defined __UINT_LEAST8_MAX__ && UCHAR_MAX <= INT_MAX
typedef unsigned char yytype_uint8;
#else
typedef short yytype_uint8;
#endif

#if defined __UINT_LEAST16_MAX__ && __UINT_LEAST16_MAX__ <= __INT_MAX__
typedef __UINT_LEAST16_TYPE__ yytype_uint16;
#elif (!defined __UINT_LEAST16_MAX__ && defined YY_STDINT_H \
       && UINT_LEAST16_MAX <= INT_MAX)
typedef uint_least16_t yytype_uint16;
#elif !defined __UINT_LEAST16_MAX__ && USHRT_MAX <= INT_MAX
typedef unsigned short yytype_uint16;
#else
typedef int yytype_uint16;
#endif

#ifndef YYPTRDIFF_T
# if defined __PTRDIFF_TYPE__ && defined __PTRDIFF_MAX__
#  define YYPTRDIFF_T __PTRDIFF_TYPE__
#  define YYPTRDIFF_MAXIMUM __PTRDIFF_MAX__
# elif defined PTRDIFF_MAX
#  ifndef ptrdiff_t
#   include <stddef.h> /* INFRINGES ON USER NAME SPACE */
#  endif
#  define YYPTRDIFF_T ptrdiff_t
#  define YYPTRDIFF_MAXIMUM PTRDIFF_MAX
# else
#  define YYPTRDIFF_T long
#  define YYPTRDIFF_MAXIMUM LONG_MAX
# endif
#endif

#ifndef YYSIZE_T
# ifdef __SIZE_TYPE__
#  define YYSIZE_T __SIZE_TYPE__
# elif defined size_t
#  define YYSIZE_T size_t
# elif defined __STDC_VERSION__ && 199901 <= __STDC_VERSION__
#  include <stddef.h> /* INFRINGES ON USER NAME SPACE */
#  define YYSIZE_T size_t
# else
#  define YYSIZE_T unsigned
# endif
#endif

#define YYSIZE_MAXIMUM                                  \
  YY_CAST (YYPTRDIFF_T,                                 \
           (YYPTRDIFF_MAXIMUM < YY_CAST (YYSIZE_T, -1)  \
            ? YYPTRDIFF_MAXIMUM                         \
            : YY_CAST (YYSIZE_T, -1)))

#define YYSIZEOF(X) YY_CAST (YYPTRDIFF_T, sizeof (X))


/* Stored state numbers (used for stacks). */
typedef yytype_int8 yy_state_t;

/* State numbers in computations.  */
typedef int yy_state_fast_t;

#ifndef YY_
# if defined YYENABLE_NLS && YYENABLE_NLS
#  if ENABLE_NLS
#   include <libintl.h> /* INFRINGES ON USER NAME SPACE */
#   define YY_(Msgid) dgettext ("bison-runtime", Msgid)
#  endif
# endif
# ifndef YY_
#  define YY_(Msgid) Msgid
# endif
#endif


#ifndef YY_ATTRIBUTE_PURE
# if defined __GNUC__ && 2 < __GNUC__ + (96 <= __GNUC_MINOR__)
#  define YY_ATTRIBUTE_PURE __attribute__ ((__pure__))
# else
#  define YY_ATTRIBUTE_PURE
# endif
#endif

#ifndef YY_ATTRIBUTE_UNUSED
# if defined __GNUC__ && 2 < __GNUC__ + (7 <= __GNUC_MINOR__)
#  define YY_ATTRIBUTE_UNUSED __attribute__ ((__unused__))
# else
#  define YY_ATTRIBUTE_UNUSED
# endif
#endif

/* Suppress unused-variable warnings by "using" E.  */
#if ! defined lint || defined __GNUC__
# define YY_USE(E) ((void) (E))
#else
# define YY_USE(E) /* empty */
#endif

#if defined __GNUC__ && ! defined __ICC && 407 <= __GNUC__ * 100 + __GNUC_MINOR__
/* Suppress an incorrect diagnostic about yylval being uninitialized.  */
# define YY_IGNORE_MAYBE_UNINITIALIZED_BEGIN                            \
    _Pragma ("GCC diagnostic push")                                     \
    _Pragma ("GCC diagnostic ignored \"-Wuninitialized\"")              \
    _Pragma ("GCC diagnostic ignored \"-Wmaybe-uninitialized\"")
# define YY_IGNORE_MAYBE_UNINITIALIZED_END      \
    _Pragma ("GCC diagnostic pop")
#else
# define YY_INITIAL_VALUE(Value) Value
#endif
#ifndef YY_IGNORE_MAYBE_UNINITIALIZED_BEGIN
# define YY_IGNORE_MAYBE_UNINITIALIZED_BEGIN
# define YY_IGNORE_MAYBE_UNINITIALIZED_END
#endif
#ifndef YY_INITIAL_VALUE
# define YY_INITIAL_VALUE(Value) /* Nothing. */
#endif

#if defined __cplusplus && defined __GNUC__ && ! defined __ICC && 6 <= __GNUC__
# define YY_IGNORE_USELESS_CAST_BEGIN                          \
    _Pragma ("GCC diagnostic push")                            \
    _Pragma ("GCC diagnostic ignored \"-Wuseless-cast\"")
# define YY_IGNORE_USELESS_CAST_END            \
    _Pragma ("GCC diagnostic pop")
#endif
#ifndef YY_IGNORE_USELESS_CAST_BEGIN
# define YY_IGNORE_USELESS_CAST_BEGIN
# define YY_IGNORE_USELESS_CAST_END
#endif


#define YY_ASSERT(E) ((void) (0 && (E)))

#if 1

/* The parser invokes alloca or malloc; define the necessary symbols.  */

# ifdef YYSTACK_USE_ALLOCA
#  if YYSTACK_USE_ALLOCA
#   ifdef __GNUC__
#    define YYSTACK_ALLOC __builtin_alloca
#   elif defined __BUILTIN_VA_ARG_INCR
#    include <alloca.h> /* INFRINGES ON USER NAME SPACE */
#   elif defined _AIX
#    define YYSTACK_ALLOC __alloca
#   elif defined _MSC_VER
#    include <malloc.h> /* INFRINGES ON USER NAME SPACE */
#    define alloca _alloca
#   else
#    define YYSTACK_ALLOC alloca
#    if ! defined _ALLOCA_H && ! defined EXIT_SUCCESS
#     include <stdlib.h> /* INFRINGES ON USER NAME SPACE */
      /* Use EXIT_SUCCESS as a witness for stdlib.h.  */
#     ifndef EXIT_SUCCESS
#      define EXIT_SUCCESS 0
#     endif
#    endif
#   endif
#  endif
# endif

# ifdef YYSTACK_ALLOC
   /* Pacify GCC's 'empty if-body' warning.  */
#  define YYSTACK_FREE(Ptr) do { /* empty */; } while (0)
#  ifndef YYSTACK_ALLOC_MAXIMUM
    /* The OS might guarantee only one guard page at the bottom of the stack,
       and a page size can be as small as 4096 bytes.  So we cannot safely
       invoke alloca (N) if N exceeds 4096.  Use a slightly smaller number
       to allow for a few compiler-allocated temporary stack slots.  */
#   define YYSTACK_ALLOC_MAXIMUM 4032 /* reasonable circa 2006 */
#  endif
# else
#  define YYSTACK_ALLOC YYMALLOC
#  define YYSTACK_FREE YYFREE
#  ifndef YYSTACK_ALLOC_MAXIMUM
#   define YYSTACK_ALLOC_MAXIMUM YYSIZE_MAXIMUM
#  endif
#  if (defined __cplusplus && ! defined EXIT_SUCCESS \
       && ! ((defined YYMALLOC || defined malloc) \
             && (defined YYFREE || defined free)))
#   include <stdlib.h> /* INFRINGES ON USER NAME SPACE */
#   ifndef EXIT_SUCCESS
#    define EXIT_SUCCESS 0
#   endif
#  endif
#  ifndef YYMALLOC
#   define YYMALLOC malloc
#   if ! defined malloc && ! defined EXIT_SUCCESS
void *malloc (YYSIZE_T); /* INFRINGES ON USER NAME SPACE */
#   endif
#  endif
#  ifndef YYFREE
#   define YYFREE free
#   if ! defined free && ! defined EXIT_SUCCESS
void free (void *); /* INFRINGES ON USER NAME SPACE */
#   endif
#  endif
# endif
#endif /* 1 */

#if (! defined yyoverflow \
     && (! defined __cplusplus \
         || (defined INI_STYPE_IS_TRIVIAL && INI_STYPE_IS_TRIVIAL)))

/* A type that is properly aligned for any stack member.  */
union yyalloc
{
  yy_state_t yyss_alloc;
  YYSTYPE yyvs_alloc;
};

/* The size of the maximum gap between one aligned stack and the next.  */
# define YYSTACK_GAP_MAXIMUM (YYSIZEOF (union yyalloc) - 1)

/* The size of an array large to enough to hold all stacks, each with
   N elements.  */
# define YYSTACK_BYTES(N) \
     ((N) * (YYSIZEOF (yy_state_t) + YYSIZEOF (YYSTYPE)) \
      + YYSTACK_GAP_MAXIMUM)

# define YYCOPY_NEEDED 1

/* Relocate STACK from its old location to the new one.  The
   local variables YYSIZE and YYSTACKSIZE give the old and new number of
   elements in the stack, and YYPTR gives the new location of the
   stack.  Advance YYPTR to a properly aligned location for the next
   stack.  */
# define YYSTACK_RELOCATE(Stack_alloc, Stack)                           \
    do                                                                  \
      {                                                                 \
        YYPTRDIFF_T yynewbytes;                                         \
        YYCOPY (&yyptr->Stack_alloc, Stack, yysize);                    \
        Stack = &yyptr->Stack_alloc;                                    \
        yynewbytes = yystacksize * YYSIZEOF (*Stack) + YYSTACK_GAP_MAXIMUM; \
        yyptr += yynewbytes / YYSIZEOF (*yyptr);                        \
      }                                                                 \
    while (0)

#endif

#if defined YYCOPY_NEEDED && YYCOPY_NEEDED
/* Copy COUNT objects from SRC to DST.  The source and destination do
   not overlap.  */
# ifndef YYCOPY
#  if defined __GNUC__ && 1 < __GNUC__
#   define YYCOPY(Dst, Src, Count) \
      __builtin_memcpy (Dst, Src, YY_CAST (YYSIZE_T, (Count)) * sizeof (*(Src)))
#  else
#   define YYCOPY(Dst, Src, Count)              \
      do                                        \
        {                                       \
          YYPTRDIFF_T yyi;                      \
          for (yyi = 0; yyi < (Count); yyi++)   \
            (Dst)[yyi] = (Src)[yyi];            \
        }                                       \
      while (0)
#  endif
# endif
#endif /* !YYCOPY_NEEDED */

/* YYFINAL -- State number of the termination state.  */
#define YYFINAL  2
/* YYLAST -- Last index in YYTABLE.  */
#define YYLAST   143

/* YYNTOKENS -- Number of terminals.  */
#define YYNTOKENS  45
/* YYNNTS -- Number of nonterminals.  */
#define YYNNTS  14
/* YYNRULES -- Number of rules.  */
#define YYNRULES  53
/* YYNSTATES -- Number of states.  */
#define YYNSTATES  76

/* YYMAXUTOK -- Last valid token kind.  */
#define YYMAXUTOK   273


/* YYTRANSLATE(TOKEN-NUM) -- Symbol number corresponding to TOKEN-NUM
   as returned by yylex, with out-of-bounds checking.  */
#define YYTRANSLATE(YYX)                                \
  (0 <= (YYX) && (YYX) <= YYMAXUTOK                     \
   ? YY_CAST (yysymbol_kind_t, yytranslate[YYX])        \
   : YYSYMBOL_YYUNDEF)

/* YYTRANSLATE[TOKEN-NUM] -- Symbol number corresponding to TOKEN-NUM
   as returned by yylex.  */
static const yytype_int8 yytranslate[] =
{
       0,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,    41,    23,     2,    31,    30,    40,    24,
      43,    44,    29,    26,    21,    27,    22,    28,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,    20,     2,
      33,    19,    34,    35,    36,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,    42,    25,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,    37,    39,    38,    32,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     1,     2,     3,     4,
       5,     6,     7,     8,     9,    10,    11,    12,    13,    14,
      15,    16,    17,    18
};

#if INI_DEBUG
  /* YYRLINE[YYN] -- Source line where rule number YYN was defined.  */
static const yytype_int16 yyrline[] =
{
       0,   359,   359,   360,   364,   371,   382,   391,   392,   396,
     397,   401,   402,   403,   404,   405,   409,   410,   414,   415,
     416,   420,   421,   422,   423,   424,   425,   429,   430,   431,
     432,   433,   434,   438,   439,   440,   441,   442,   443,   444,
     448,   449,   454,   455,   459,   460,   461,   462,   463,   467,
     468,   469,   474,   475
};
#endif

/** Accessing symbol of state STATE.  */
#define YY_ACCESSING_SYMBOL(State) YY_CAST (yysymbol_kind_t, yystos[State])

#if 1
/* The user-facing name of the symbol whose (internal) number is
   YYSYMBOL.  No bounds checking.  */
static const char *yysymbol_name (yysymbol_kind_t yysymbol) YY_ATTRIBUTE_UNUSED;

/* YYTNAME[SYMBOL-NUM] -- String name of the symbol SYMBOL-NUM.
   First, the terminals, then, starting at YYNTOKENS, nonterminals.  */
static const char *const yytname[] =
{
  "\"end of file\"", "error", "\"invalid token\"", "TC_SECTION", "TC_RAW",
  "TC_CONSTANT", "TC_NUMBER", "TC_STRING", "TC_WHITESPACE", "TC_LABEL",
  "TC_OFFSET", "TC_DOLLAR_CURLY", "TC_VARNAME", "TC_QUOTED_STRING",
  "TC_FALLBACK", "BOOL_TRUE", "BOOL_FALSE", "NULL_NULL", "END_OF_LINE",
  "'='", "':'", "','", "'.'", "'\"'", "'\\''", "'^'", "'+'", "'-'", "'/'",
  "'*'", "'%'", "'$'", "'~'", "'<'", "'>'", "'?'", "'@'", "'{'", "'}'",
  "'|'", "'&'", "'!'", "']'", "'('", "')'", "$accept", "statement_list",
  "statement", "section_string_or_value", "string_or_value",
  "option_offset", "encapsed_list", "var_string_list_section",
  "var_string_list", "expr", "cfg_var_ref", "fallback", "constant_literal",
  "constant_string", YY_NULLPTR
};

static const char *
yysymbol_name (yysymbol_kind_t yysymbol)
{
  return yytname[yysymbol];
}
#endif

#ifdef YYPRINT
/* YYTOKNUM[NUM] -- (External) token number corresponding to the
   (internal) symbol number NUM (which must be that of a token).  */
static const yytype_int16 yytoknum[] =
{
       0,   256,   257,   258,   259,   260,   261,   262,   263,   264,
     265,   266,   267,   268,   269,   270,   271,   272,   273,    61,
      58,    44,    46,    34,    39,    94,    43,    45,    47,    42,
      37,    36,   126,    60,    62,    63,    64,   123,   125,   124,
      38,    33,    93,    40,    41
};
#endif

#define YYPACT_NINF (-46)

#define yypact_value_is_default(Yyn) \
  ((Yyn) == YYPACT_NINF)

#define YYTABLE_NINF (-1)

#define yytable_value_is_error(Yyn) \
  0

  /* YYPACT[STATE-NUM] -- Index in YYTABLE of the portion describing
     STATE-NUM.  */
static const yytype_int8 yypact[] =
{
     -46,   118,   -46,    73,   -17,    81,   -46,   -46,   -46,   -46,
     -46,   -46,   -46,     0,   -46,   -34,    94,   -46,   -46,    -1,
     -46,   -46,   -46,   -46,   -46,   -46,   -31,   102,   -46,   -46,
       6,    59,   -46,   -46,   -46,   -46,   -46,   -46,   -46,   -46,
      28,    28,    28,   -46,   102,    25,    80,     2,   -46,   -46,
     -46,    81,   -46,   -46,   -46,   -46,   109,   -46,   -46,    72,
      28,    28,    28,   -46,    -1,   120,   102,   -20,   -46,   -46,
     -46,   -46,   -46,   -46,   -46,   -46
};

  /* YYDEFACT[STATE-NUM] -- Default reduction number in state STATE-NUM.
     Performed when YYTABLE does not specify something else to do.  Zero
     means the default is an error.  */
static const yytype_int8 yydefact[] =
{
       3,     0,     1,    10,     7,    17,     8,     2,    45,    44,
      46,    47,    48,     0,    20,     0,     9,    21,    22,     0,
      50,    49,    51,    52,    53,    20,     0,    16,    27,    28,
       0,     0,     4,    20,    24,    25,    12,    13,    14,    15,
       0,     0,     0,     5,    33,    11,     0,     0,    20,    30,
      31,    43,    40,    19,    23,    18,     0,    37,    38,     0,
       0,     0,     0,    29,     0,     0,    42,     0,    26,    39,
      36,    34,    35,     6,    32,    41
};

  /* YYPGOTO[NTERM-NUM].  */
static const yytype_int8 yypgoto[] =
{
     -46,   -46,   -46,   -46,   -45,   -46,     4,   -46,    -4,    14,
      -3,   -46,     7,   -18
};

  /* YYDEFGOTO[NTERM-NUM].  */
static const yytype_int8 yydefgoto[] =
{
       0,     1,     7,    15,    43,    26,    31,    16,    44,    45,
      28,    67,    18,    29
};

  /* YYTABLE[YYPACT[STATE-NUM]] -- What to do in state STATE-NUM.  If
     positive, shift that token.  If negative, reduce the rule whose
     number is the opposite.  If YYTABLE_NINF, syntax error.  */
static const yytype_int8 yytable[] =
{
      17,    27,    19,    20,    21,    22,    23,    24,    32,    50,
      13,    47,    30,    34,    36,    37,    38,    39,    75,    73,
      51,    64,    25,    35,    49,     0,    50,     0,    55,    46,
       0,    40,    20,    21,    22,    23,    24,    56,     0,    13,
      41,    49,    42,    55,    52,     0,     0,    66,    50,     0,
      60,    25,    65,    55,    57,    58,    59,     0,     0,     0,
      40,     0,    55,    49,    61,    62,     0,     0,     0,    41,
      13,    42,    53,     0,    70,    71,    72,     8,     9,    10,
      11,    12,    54,     0,    13,    20,    21,    22,    23,    24,
       0,    13,    13,    53,     0,     0,    14,    60,     8,     9,
      10,    11,    12,    63,    25,    13,    20,    21,    22,    23,
      24,    61,    62,    13,     0,     0,    69,    33,     2,     0,
      13,     3,    53,     0,     0,    48,     0,     4,     5,     0,
       0,    13,    68,    53,     0,     0,     6,     0,     0,     0,
       0,     0,     0,    74
};

static const yytype_int8 yycheck[] =
{
       3,     5,    19,     4,     5,     6,     7,     8,    42,    27,
      11,    42,    12,    16,    15,    16,    17,    18,    38,    64,
      14,    19,    23,    16,    27,    -1,    44,    -1,    31,    25,
      -1,    32,     4,     5,     6,     7,     8,    33,    -1,    11,
      41,    44,    43,    46,    38,    -1,    -1,    51,    66,    -1,
      25,    23,    48,    56,    40,    41,    42,    -1,    -1,    -1,
      32,    -1,    65,    66,    39,    40,    -1,    -1,    -1,    41,
      11,    43,    13,    -1,    60,    61,    62,     4,     5,     6,
       7,     8,    23,    -1,    11,     4,     5,     6,     7,     8,
      -1,    11,    11,    13,    -1,    -1,    23,    25,     4,     5,
       6,     7,     8,    23,    23,    11,     4,     5,     6,     7,
       8,    39,    40,    11,    -1,    -1,    44,    23,     0,    -1,
      11,     3,    13,    -1,    -1,    23,    -1,     9,    10,    -1,
      -1,    11,    23,    13,    -1,    -1,    18,    -1,    -1,    -1,
      -1,    -1,    -1,    23
};

  /* YYSTOS[STATE-NUM] -- The (internal number of the) accessing
     symbol of state STATE-NUM.  */
static const yytype_int8 yystos[] =
{
       0,    46,     0,     3,     9,    10,    18,    47,     4,     5,
       6,     7,     8,    11,    23,    48,    52,    55,    57,    19,
       4,     5,     6,     7,     8,    23,    50,    53,    55,    58,
      12,    51,    42,    23,    55,    57,    15,    16,    17,    18,
      32,    41,    43,    49,    53,    54,    51,    42,    23,    55,
      58,    14,    38,    13,    23,    55,    51,    54,    54,    54,
      25,    39,    40,    23,    19,    51,    53,    56,    23,    44,
      54,    54,    54,    49,    23,    38
};

  /* YYR1[YYN] -- Symbol number of symbol that rule YYN derives.  */
static const yytype_int8 yyr1[] =
{
       0,    45,    46,    46,    47,    47,    47,    47,    47,    48,
      48,    49,    49,    49,    49,    49,    50,    50,    51,    51,
      51,    52,    52,    52,    52,    52,    52,    53,    53,    53,
      53,    53,    53,    54,    54,    54,    54,    54,    54,    54,
      55,    55,    56,    56,    57,    57,    57,    57,    57,    58,
      58,    58,    58,    58
};

  /* YYR2[YYN] -- Number of symbols on the right hand side of rule YYN.  */
static const yytype_int8 yyr2[] =
{
       0,     2,     2,     0,     3,     3,     5,     1,     1,     1,
       0,     1,     1,     1,     1,     1,     1,     0,     2,     2,
       0,     1,     1,     3,     2,     2,     4,     1,     1,     3,
       2,     2,     4,     1,     3,     3,     3,     2,     2,     3,
       3,     5,     1,     0,     1,     1,     1,     1,     1,     1,
       1,     1,     1,     1
};


enum { YYENOMEM = -2 };

#define yyerrok         (yyerrstatus = 0)
#define yyclearin       (yychar = INI_EMPTY)

#define YYACCEPT        goto yyacceptlab
#define YYABORT         goto yyabortlab
#define YYERROR         goto yyerrorlab


#define YYRECOVERING()  (!!yyerrstatus)

#define YYBACKUP(Token, Value)                                    \
  do                                                              \
    if (yychar == INI_EMPTY)                                        \
      {                                                           \
        yychar = (Token);                                         \
        yylval = (Value);                                         \
        YYPOPSTACK (yylen);                                       \
        yystate = *yyssp;                                         \
        goto yybackup;                                            \
      }                                                           \
    else                                                          \
      {                                                           \
        yyerror (YY_("syntax error: cannot back up")); \
        YYERROR;                                                  \
      }                                                           \
  while (0)

/* Backward compatibility with an undocumented macro.
   Use INI_error or INI_UNDEF. */
#define YYERRCODE INI_UNDEF


/* Enable debugging if requested.  */
#if INI_DEBUG

# ifndef YYFPRINTF
#  include <stdio.h> /* INFRINGES ON USER NAME SPACE */
#  define YYFPRINTF fprintf
# endif

# define YYDPRINTF(Args)                        \
do {                                            \
  if (yydebug)                                  \
    YYFPRINTF Args;                             \
} while (0)

/* This macro is provided for backward compatibility. */
# ifndef YY_LOCATION_PRINT
#  define YY_LOCATION_PRINT(File, Loc) ((void) 0)
# endif


# define YY_SYMBOL_PRINT(Title, Kind, Value, Location)                    \
do {                                                                      \
  if (yydebug)                                                            \
    {                                                                     \
      YYFPRINTF (stderr, "%s ", Title);                                   \
      yy_symbol_print (stderr,                                            \
                  Kind, Value); \
      YYFPRINTF (stderr, "\n");                                           \
    }                                                                     \
} while (0)


/*-----------------------------------.
| Print this symbol's value on YYO.  |
`-----------------------------------*/

static void
yy_symbol_value_print (FILE *yyo,
                       yysymbol_kind_t yykind, YYSTYPE const * const yyvaluep)
{
  FILE *yyoutput = yyo;
  YY_USE (yyoutput);
  if (!yyvaluep)
    return;
# ifdef YYPRINT
  if (yykind < YYNTOKENS)
    YYPRINT (yyo, yytoknum[yykind], *yyvaluep);
# endif
  YY_IGNORE_MAYBE_UNINITIALIZED_BEGIN
  YY_USE (yykind);
  YY_IGNORE_MAYBE_UNINITIALIZED_END
}


/*---------------------------.
| Print this symbol on YYO.  |
`---------------------------*/

static void
yy_symbol_print (FILE *yyo,
                 yysymbol_kind_t yykind, YYSTYPE const * const yyvaluep)
{
  YYFPRINTF (yyo, "%s %s (",
             yykind < YYNTOKENS ? "token" : "nterm", yysymbol_name (yykind));

  yy_symbol_value_print (yyo, yykind, yyvaluep);
  YYFPRINTF (yyo, ")");
}

/*------------------------------------------------------------------.
| yy_stack_print -- Print the state stack from its BOTTOM up to its |
| TOP (included).                                                   |
`------------------------------------------------------------------*/

static void
yy_stack_print (yy_state_t *yybottom, yy_state_t *yytop)
{
  YYFPRINTF (stderr, "Stack now");
  for (; yybottom <= yytop; yybottom++)
    {
      int yybot = *yybottom;
      YYFPRINTF (stderr, " %d", yybot);
    }
  YYFPRINTF (stderr, "\n");
}

# define YY_STACK_PRINT(Bottom, Top)                            \
do {                                                            \
  if (yydebug)                                                  \
    yy_stack_print ((Bottom), (Top));                           \
} while (0)


/*------------------------------------------------.
| Report that the YYRULE is going to be reduced.  |
`------------------------------------------------*/

static void
yy_reduce_print (yy_state_t *yyssp, YYSTYPE *yyvsp,
                 int yyrule)
{
  int yylno = yyrline[yyrule];
  int yynrhs = yyr2[yyrule];
  int yyi;
  YYFPRINTF (stderr, "Reducing stack by rule %d (line %d):\n",
             yyrule - 1, yylno);
  /* The symbols being reduced.  */
  for (yyi = 0; yyi < yynrhs; yyi++)
    {
      YYFPRINTF (stderr, "   $%d = ", yyi + 1);
      yy_symbol_print (stderr,
                       YY_ACCESSING_SYMBOL (+yyssp[yyi + 1 - yynrhs]),
                       &yyvsp[(yyi + 1) - (yynrhs)]);
      YYFPRINTF (stderr, "\n");
    }
}

# define YY_REDUCE_PRINT(Rule)          \
do {                                    \
  if (yydebug)                          \
    yy_reduce_print (yyssp, yyvsp, Rule); \
} while (0)

/* Nonzero means print parse trace.  It is left uninitialized so that
   multiple parsers can coexist.  */
int yydebug;
#else /* !INI_DEBUG */
# define YYDPRINTF(Args) ((void) 0)
# define YY_SYMBOL_PRINT(Title, Kind, Value, Location)
# define YY_STACK_PRINT(Bottom, Top)
# define YY_REDUCE_PRINT(Rule)
#endif /* !INI_DEBUG */


/* YYINITDEPTH -- initial size of the parser's stacks.  */
#ifndef YYINITDEPTH
# define YYINITDEPTH 200
#endif

/* YYMAXDEPTH -- maximum size the stacks can grow to (effective only
   if the built-in stack extension method is used).

   Do not make this value too large; the results are undefined if
   YYSTACK_ALLOC_MAXIMUM < YYSTACK_BYTES (YYMAXDEPTH)
   evaluated with infinite-precision integer arithmetic.  */

#ifndef YYMAXDEPTH
# define YYMAXDEPTH 10000
#endif


/* Context of a parse error.  */
typedef struct
{
  yy_state_t *yyssp;
  yysymbol_kind_t yytoken;
} yypcontext_t;

/* Put in YYARG at most YYARGN of the expected tokens given the
   current YYCTX, and return the number of tokens stored in YYARG.  If
   YYARG is null, return the number of expected tokens (guaranteed to
   be less than YYNTOKENS).  Return YYENOMEM on memory exhaustion.
   Return 0 if there are more than YYARGN expected tokens, yet fill
   YYARG up to YYARGN. */
static int
yypcontext_expected_tokens (const yypcontext_t *yyctx,
                            yysymbol_kind_t yyarg[], int yyargn)
{
  /* Actual size of YYARG. */
  int yycount = 0;
  int yyn = yypact[+*yyctx->yyssp];
  if (!yypact_value_is_default (yyn))
    {
      /* Start YYX at -YYN if negative to avoid negative indexes in
         YYCHECK.  In other words, skip the first -YYN actions for
         this state because they are default actions.  */
      int yyxbegin = yyn < 0 ? -yyn : 0;
      /* Stay within bounds of both yycheck and yytname.  */
      int yychecklim = YYLAST - yyn + 1;
      int yyxend = yychecklim < YYNTOKENS ? yychecklim : YYNTOKENS;
      int yyx;
      for (yyx = yyxbegin; yyx < yyxend; ++yyx)
        if (yycheck[yyx + yyn] == yyx && yyx != YYSYMBOL_YYerror
            && !yytable_value_is_error (yytable[yyx + yyn]))
          {
            if (!yyarg)
              ++yycount;
            else if (yycount == yyargn)
              return 0;
            else
              yyarg[yycount++] = YY_CAST (yysymbol_kind_t, yyx);
          }
    }
  if (yyarg && yycount == 0 && 0 < yyargn)
    yyarg[0] = YYSYMBOL_YYEMPTY;
  return yycount;
}




#ifndef yystrlen
# if defined __GLIBC__ && defined _STRING_H
#  define yystrlen(S) (YY_CAST (YYPTRDIFF_T, strlen (S)))
# else
/* Return the length of YYSTR.  */
static YYPTRDIFF_T
yystrlen (const char *yystr)
{
  YYPTRDIFF_T yylen;
  for (yylen = 0; yystr[yylen]; yylen++)
    continue;
  return yylen;
}
# endif
#endif

#ifndef yystpcpy
# if defined __GLIBC__ && defined _STRING_H && defined _GNU_SOURCE
#  define yystpcpy stpcpy
# else
/* Copy YYSRC to YYDEST, returning the address of the terminating '\0' in
   YYDEST.  */
static char *
yystpcpy (char *yydest, const char *yysrc)
{
  char *yyd = yydest;
  const char *yys = yysrc;

  while ((*yyd++ = *yys++) != '\0')
    continue;

  return yyd - 1;
}
# endif
#endif

#ifndef yytnamerr
/* Copy to YYRES the contents of YYSTR after stripping away unnecessary
   quotes and backslashes, so that it's suitable for yyerror.  The
   heuristic is that double-quoting is unnecessary unless the string
   contains an apostrophe, a comma, or backslash (other than
   backslash-backslash).  YYSTR is taken from yytname.  If YYRES is
   null, do not copy; instead, return the length of what the result
   would have been.  */
static YYPTRDIFF_T
yytnamerr (char *yyres, const char *yystr)
{
  if (*yystr == '"')
    {
      YYPTRDIFF_T yyn = 0;
      char const *yyp = yystr;
      for (;;)
        switch (*++yyp)
          {
          case '\'':
          case ',':
            goto do_not_strip_quotes;

          case '\\':
            if (*++yyp != '\\')
              goto do_not_strip_quotes;
            else
              goto append;

          append:
          default:
            if (yyres)
              yyres[yyn] = *yyp;
            yyn++;
            break;

          case '"':
            if (yyres)
              yyres[yyn] = '\0';
            return yyn;
          }
    do_not_strip_quotes: ;
    }

  if (yyres)
    return yystpcpy (yyres, yystr) - yyres;
  else
    return yystrlen (yystr);
}
#endif


static int
yy_syntax_error_arguments (const yypcontext_t *yyctx,
                           yysymbol_kind_t yyarg[], int yyargn)
{
  /* Actual size of YYARG. */
  int yycount = 0;
  /* There are many possibilities here to consider:
     - If this state is a consistent state with a default action, then
       the only way this function was invoked is if the default action
       is an error action.  In that case, don't check for expected
       tokens because there are none.
     - The only way there can be no lookahead present (in yychar) is if
       this state is a consistent state with a default action.  Thus,
       detecting the absence of a lookahead is sufficient to determine
       that there is no unexpected or expected token to report.  In that
       case, just report a simple "syntax error".
     - Don't assume there isn't a lookahead just because this state is a
       consistent state with a default action.  There might have been a
       previous inconsistent state, consistent state with a non-default
       action, or user semantic action that manipulated yychar.
     - Of course, the expected token list depends on states to have
       correct lookahead information, and it depends on the parser not
       to perform extra reductions after fetching a lookahead from the
       scanner and before detecting a syntax error.  Thus, state merging
       (from LALR or IELR) and default reductions corrupt the expected
       token list.  However, the list is correct for canonical LR with
       one exception: it will still contain any token that will not be
       accepted due to an error action in a later state.
  */
  if (yyctx->yytoken != YYSYMBOL_YYEMPTY)
    {
      int yyn;
      if (yyarg)
        yyarg[yycount] = yyctx->yytoken;
      ++yycount;
      yyn = yypcontext_expected_tokens (yyctx,
                                        yyarg ? yyarg + 1 : yyarg, yyargn - 1);
      if (yyn == YYENOMEM)
        return YYENOMEM;
      else
        yycount += yyn;
    }
  return yycount;
}

/* Copy into *YYMSG, which is of size *YYMSG_ALLOC, an error message
   about the unexpected token YYTOKEN for the state stack whose top is
   YYSSP.

   Return 0 if *YYMSG was successfully written.  Return -1 if *YYMSG is
   not large enough to hold the message.  In that case, also set
   *YYMSG_ALLOC to the required number of bytes.  Return YYENOMEM if the
   required number of bytes is too large to store.  */
static int
yysyntax_error (YYPTRDIFF_T *yymsg_alloc, char **yymsg,
                const yypcontext_t *yyctx)
{
  enum { YYARGS_MAX = 5 };
  /* Internationalized format string. */
  const char *yyformat = YY_NULLPTR;
  /* Arguments of yyformat: reported tokens (one for the "unexpected",
     one per "expected"). */
  yysymbol_kind_t yyarg[YYARGS_MAX];
  /* Cumulated lengths of YYARG.  */
  YYPTRDIFF_T yysize = 0;

  /* Actual size of YYARG. */
  int yycount = yy_syntax_error_arguments (yyctx, yyarg, YYARGS_MAX);
  if (yycount == YYENOMEM)
    return YYENOMEM;

  switch (yycount)
    {
#define YYCASE_(N, S)                       \
      case N:                               \
        yyformat = S;                       \
        break
    default: /* Avoid compiler warnings. */
      YYCASE_(0, YY_("syntax error"));
      YYCASE_(1, YY_("syntax error, unexpected %s"));
      YYCASE_(2, YY_("syntax error, unexpected %s, expecting %s"));
      YYCASE_(3, YY_("syntax error, unexpected %s, expecting %s or %s"));
      YYCASE_(4, YY_("syntax error, unexpected %s, expecting %s or %s or %s"));
      YYCASE_(5, YY_("syntax error, unexpected %s, expecting %s or %s or %s or %s"));
#undef YYCASE_
    }

  /* Compute error message size.  Don't count the "%s"s, but reserve
     room for the terminator.  */
  yysize = yystrlen (yyformat) - 2 * yycount + 1;
  {
    int yyi;
    for (yyi = 0; yyi < yycount; ++yyi)
      {
        YYPTRDIFF_T yysize1
          = yysize + yytnamerr (YY_NULLPTR, yytname[yyarg[yyi]]);
        if (yysize <= yysize1 && yysize1 <= YYSTACK_ALLOC_MAXIMUM)
          yysize = yysize1;
        else
          return YYENOMEM;
      }
  }

  if (*yymsg_alloc < yysize)
    {
      *yymsg_alloc = 2 * yysize;
      if (! (yysize <= *yymsg_alloc
             && *yymsg_alloc <= YYSTACK_ALLOC_MAXIMUM))
        *yymsg_alloc = YYSTACK_ALLOC_MAXIMUM;
      return -1;
    }

  /* Avoid sprintf, as that infringes on the user's name space.
     Don't have undefined behavior even if the translation
     produced a string with the wrong number of "%s"s.  */
  {
    char *yyp = *yymsg;
    int yyi = 0;
    while ((*yyp = *yyformat) != '\0')
      if (*yyp == '%' && yyformat[1] == 's' && yyi < yycount)
        {
          yyp += yytnamerr (yyp, yytname[yyarg[yyi++]]);
          yyformat += 2;
        }
      else
        {
          ++yyp;
          ++yyformat;
        }
  }
  return 0;
}


/*-----------------------------------------------.
| Release the memory associated to this symbol.  |
`-----------------------------------------------*/

static void
yydestruct (const char *yymsg,
            yysymbol_kind_t yykind, YYSTYPE *yyvaluep)
{
  YY_USE (yyvaluep);
  if (!yymsg)
    yymsg = "Deleting";
  YY_SYMBOL_PRINT (yymsg, yykind, yyvaluep, yylocationp);

  YY_IGNORE_MAYBE_UNINITIALIZED_BEGIN
  switch (yykind)
    {
    case YYSYMBOL_TC_RAW: /* TC_RAW  */
#line 354 "/home/smamran09/php-src/Zend/zend_ini_parser.y"
            { zval_ini_dtor(&(*yyvaluep)); }
#line 1530 "/home/smamran09/php-src/Zend/zend_ini_parser.c"
        break;

    case YYSYMBOL_TC_CONSTANT: /* TC_CONSTANT  */
#line 354 "/home/smamran09/php-src/Zend/zend_ini_parser.y"
            { zval_ini_dtor(&(*yyvaluep)); }
#line 1536 "/home/smamran09/php-src/Zend/zend_ini_parser.c"
        break;

    case YYSYMBOL_TC_NUMBER: /* TC_NUMBER  */
#line 354 "/home/smamran09/php-src/Zend/zend_ini_parser.y"
            { zval_ini_dtor(&(*yyvaluep)); }
#line 1542 "/home/smamran09/php-src/Zend/zend_ini_parser.c"
        break;

    case YYSYMBOL_TC_STRING: /* TC_STRING  */
#line 354 "/home/smamran09/php-src/Zend/zend_ini_parser.y"
            { zval_ini_dtor(&(*yyvaluep)); }
#line 1548 "/home/smamran09/php-src/Zend/zend_ini_parser.c"
        break;

    case YYSYMBOL_TC_WHITESPACE: /* TC_WHITESPACE  */
#line 354 "/home/smamran09/php-src/Zend/zend_ini_parser.y"
            { zval_ini_dtor(&(*yyvaluep)); }
#line 1554 "/home/smamran09/php-src/Zend/zend_ini_parser.c"
        break;

    case YYSYMBOL_TC_LABEL: /* TC_LABEL  */
#line 354 "/home/smamran09/php-src/Zend/zend_ini_parser.y"
            { zval_ini_dtor(&(*yyvaluep)); }
#line 1560 "/home/smamran09/php-src/Zend/zend_ini_parser.c"
        break;

    case YYSYMBOL_TC_OFFSET: /* TC_OFFSET  */
#line 354 "/home/smamran09/php-src/Zend/zend_ini_parser.y"
            { zval_ini_dtor(&(*yyvaluep)); }
#line 1566 "/home/smamran09/php-src/Zend/zend_ini_parser.c"
        break;

    case YYSYMBOL_TC_VARNAME: /* TC_VARNAME  */
#line 354 "/home/smamran09/php-src/Zend/zend_ini_parser.y"
            { zval_ini_dtor(&(*yyvaluep)); }
#line 1572 "/home/smamran09/php-src/Zend/zend_ini_parser.c"
        break;

    case YYSYMBOL_BOOL_TRUE: /* BOOL_TRUE  */
#line 354 "/home/smamran09/php-src/Zend/zend_ini_parser.y"
            { zval_ini_dtor(&(*yyvaluep)); }
#line 1578 "/home/smamran09/php-src/Zend/zend_ini_parser.c"
        break;

    case YYSYMBOL_BOOL_FALSE: /* BOOL_FALSE  */
#line 354 "/home/smamran09/php-src/Zend/zend_ini_parser.y"
            { zval_ini_dtor(&(*yyvaluep)); }
#line 1584 "/home/smamran09/php-src/Zend/zend_ini_parser.c"
        break;

    case YYSYMBOL_NULL_NULL: /* NULL_NULL  */
#line 354 "/home/smamran09/php-src/Zend/zend_ini_parser.y"
            { zval_ini_dtor(&(*yyvaluep)); }
#line 1590 "/home/smamran09/php-src/Zend/zend_ini_parser.c"
        break;

    case YYSYMBOL_section_string_or_value: /* section_string_or_value  */
#line 354 "/home/smamran09/php-src/Zend/zend_ini_parser.y"
            { zval_ini_dtor(&(*yyvaluep)); }
#line 1596 "/home/smamran09/php-src/Zend/zend_ini_parser.c"
        break;

    case YYSYMBOL_string_or_value: /* string_or_value  */
#line 354 "/home/smamran09/php-src/Zend/zend_ini_parser.y"
            { zval_ini_dtor(&(*yyvaluep)); }
#line 1602 "/home/smamran09/php-src/Zend/zend_ini_parser.c"
        break;

    case YYSYMBOL_option_offset: /* option_offset  */
#line 354 "/home/smamran09/php-src/Zend/zend_ini_parser.y"
            { zval_ini_dtor(&(*yyvaluep)); }
#line 1608 "/home/smamran09/php-src/Zend/zend_ini_parser.c"
        break;

    case YYSYMBOL_encapsed_list: /* encapsed_list  */
#line 354 "/home/smamran09/php-src/Zend/zend_ini_parser.y"
            { zval_ini_dtor(&(*yyvaluep)); }
#line 1614 "/home/smamran09/php-src/Zend/zend_ini_parser.c"
        break;

    case YYSYMBOL_var_string_list_section: /* var_string_list_section  */
#line 354 "/home/smamran09/php-src/Zend/zend_ini_parser.y"
            { zval_ini_dtor(&(*yyvaluep)); }
#line 1620 "/home/smamran09/php-src/Zend/zend_ini_parser.c"
        break;

    case YYSYMBOL_var_string_list: /* var_string_list  */
#line 354 "/home/smamran09/php-src/Zend/zend_ini_parser.y"
            { zval_ini_dtor(&(*yyvaluep)); }
#line 1626 "/home/smamran09/php-src/Zend/zend_ini_parser.c"
        break;

    case YYSYMBOL_expr: /* expr  */
#line 354 "/home/smamran09/php-src/Zend/zend_ini_parser.y"
            { zval_ini_dtor(&(*yyvaluep)); }
#line 1632 "/home/smamran09/php-src/Zend/zend_ini_parser.c"
        break;

    case YYSYMBOL_cfg_var_ref: /* cfg_var_ref  */
#line 354 "/home/smamran09/php-src/Zend/zend_ini_parser.y"
            { zval_ini_dtor(&(*yyvaluep)); }
#line 1638 "/home/smamran09/php-src/Zend/zend_ini_parser.c"
        break;

    case YYSYMBOL_constant_literal: /* constant_literal  */
#line 354 "/home/smamran09/php-src/Zend/zend_ini_parser.y"
            { zval_ini_dtor(&(*yyvaluep)); }
#line 1644 "/home/smamran09/php-src/Zend/zend_ini_parser.c"
        break;

    case YYSYMBOL_constant_string: /* constant_string  */
#line 354 "/home/smamran09/php-src/Zend/zend_ini_parser.y"
            { zval_ini_dtor(&(*yyvaluep)); }
#line 1650 "/home/smamran09/php-src/Zend/zend_ini_parser.c"
        break;

      default:
        break;
    }
  YY_IGNORE_MAYBE_UNINITIALIZED_END
}






/*----------.
| yyparse.  |
`----------*/

int
yyparse (void)
{
/* Lookahead token kind.  */
int yychar;


/* The semantic value of the lookahead symbol.  */
/* Default value used for initialization, for pacifying older GCCs
   or non-GCC compilers.  */
YY_INITIAL_VALUE (static YYSTYPE yyval_default;)
YYSTYPE yylval YY_INITIAL_VALUE (= yyval_default);

    /* Number of syntax errors so far.  */
    int yynerrs = 0;

    yy_state_fast_t yystate = 0;
    /* Number of tokens to shift before error messages enabled.  */
    int yyerrstatus = 0;

    /* Refer to the stacks through separate pointers, to allow yyoverflow
       to reallocate them elsewhere.  */

    /* Their size.  */
    YYPTRDIFF_T yystacksize = YYINITDEPTH;

    /* The state stack: array, bottom, top.  */
    yy_state_t yyssa[YYINITDEPTH];
    yy_state_t *yyss = yyssa;
    yy_state_t *yyssp = yyss;

    /* The semantic value stack: array, bottom, top.  */
    YYSTYPE yyvsa[YYINITDEPTH];
    YYSTYPE *yyvs = yyvsa;
    YYSTYPE *yyvsp = yyvs;

  int yyn;
  /* The return value of yyparse.  */
  int yyresult;
  /* Lookahead symbol kind.  */
  yysymbol_kind_t yytoken = YYSYMBOL_YYEMPTY;
  /* The variables used to return semantic value and location from the
     action routines.  */
  YYSTYPE yyval;

  /* Buffer for error messages, and its allocated size.  */
  char yymsgbuf[128];
  char *yymsg = yymsgbuf;
  YYPTRDIFF_T yymsg_alloc = sizeof yymsgbuf;

#define YYPOPSTACK(N)   (yyvsp -= (N), yyssp -= (N))

  /* The number of symbols on the RHS of the reduced rule.
     Keep to zero when no symbol should be popped.  */
  int yylen = 0;

  YYDPRINTF ((stderr, "Starting parse\n"));

  yychar = INI_EMPTY; /* Cause a token to be read.  */
  goto yysetstate;


/*------------------------------------------------------------.
| yynewstate -- push a new state, which is found in yystate.  |
`------------------------------------------------------------*/
yynewstate:
  /* In all cases, when you get here, the value and location stacks
     have just been pushed.  So pushing a state here evens the stacks.  */
  yyssp++;


/*--------------------------------------------------------------------.
| yysetstate -- set current state (the top of the stack) to yystate.  |
`--------------------------------------------------------------------*/
yysetstate:
  YYDPRINTF ((stderr, "Entering state %d\n", yystate));
  YY_ASSERT (0 <= yystate && yystate < YYNSTATES);
  YY_IGNORE_USELESS_CAST_BEGIN
  *yyssp = YY_CAST (yy_state_t, yystate);
  YY_IGNORE_USELESS_CAST_END
  YY_STACK_PRINT (yyss, yyssp);

  if (yyss + yystacksize - 1 <= yyssp)
#if !defined yyoverflow && !defined YYSTACK_RELOCATE
    goto yyexhaustedlab;
#else
    {
      /* Get the current used size of the three stacks, in elements.  */
      YYPTRDIFF_T yysize = yyssp - yyss + 1;

# if defined yyoverflow
      {
        /* Give user a chance to reallocate the stack.  Use copies of
           these so that the &'s don't force the real ones into
           memory.  */
        yy_state_t *yyss1 = yyss;
        YYSTYPE *yyvs1 = yyvs;

        /* Each stack pointer address is followed by the size of the
           data in use in that stack, in bytes.  This used to be a
           conditional around just the two extra args, but that might
           be undefined if yyoverflow is a macro.  */
        yyoverflow (YY_("memory exhausted"),
                    &yyss1, yysize * YYSIZEOF (*yyssp),
                    &yyvs1, yysize * YYSIZEOF (*yyvsp),
                    &yystacksize);
        yyss = yyss1;
        yyvs = yyvs1;
      }
# else /* defined YYSTACK_RELOCATE */
      /* Extend the stack our own way.  */
      if (YYMAXDEPTH <= yystacksize)
        goto yyexhaustedlab;
      yystacksize *= 2;
      if (YYMAXDEPTH < yystacksize)
        yystacksize = YYMAXDEPTH;

      {
        yy_state_t *yyss1 = yyss;
        union yyalloc *yyptr =
          YY_CAST (union yyalloc *,
                   YYSTACK_ALLOC (YY_CAST (YYSIZE_T, YYSTACK_BYTES (yystacksize))));
        if (! yyptr)
          goto yyexhaustedlab;
        YYSTACK_RELOCATE (yyss_alloc, yyss);
        YYSTACK_RELOCATE (yyvs_alloc, yyvs);
#  undef YYSTACK_RELOCATE
        if (yyss1 != yyssa)
          YYSTACK_FREE (yyss1);
      }
# endif

      yyssp = yyss + yysize - 1;
      yyvsp = yyvs + yysize - 1;

      YY_IGNORE_USELESS_CAST_BEGIN
      YYDPRINTF ((stderr, "Stack size increased to %ld\n",
                  YY_CAST (long, yystacksize)));
      YY_IGNORE_USELESS_CAST_END

      if (yyss + yystacksize - 1 <= yyssp)
        YYABORT;
    }
#endif /* !defined yyoverflow && !defined YYSTACK_RELOCATE */

  if (yystate == YYFINAL)
    YYACCEPT;

  goto yybackup;


/*-----------.
| yybackup.  |
`-----------*/
yybackup:
  /* Do appropriate processing given the current state.  Read a
     lookahead token if we need one and don't already have one.  */

  /* First try to decide what to do without reference to lookahead token.  */
  yyn = yypact[yystate];
  if (yypact_value_is_default (yyn))
    goto yydefault;

  /* Not known => get a lookahead token if don't already have one.  */

  /* YYCHAR is either empty, or end-of-input, or a valid lookahead.  */
  if (yychar == INI_EMPTY)
    {
      YYDPRINTF ((stderr, "Reading a token\n"));
      yychar = yylex (&yylval);
    }

  if (yychar <= END)
    {
      yychar = END;
      yytoken = YYSYMBOL_YYEOF;
      YYDPRINTF ((stderr, "Now at end of input.\n"));
    }
  else if (yychar == INI_error)
    {
      /* The scanner already issued an error message, process directly
         to error recovery.  But do not keep the error token as
         lookahead, it is too special and may lead us to an endless
         loop in error recovery. */
      yychar = INI_UNDEF;
      yytoken = YYSYMBOL_YYerror;
      goto yyerrlab1;
    }
  else
    {
      yytoken = YYTRANSLATE (yychar);
      YY_SYMBOL_PRINT ("Next token is", yytoken, &yylval, &yylloc);
    }

  /* If the proper action on seeing token YYTOKEN is to reduce or to
     detect an error, take that action.  */
  yyn += yytoken;
  if (yyn < 0 || YYLAST < yyn || yycheck[yyn] != yytoken)
    goto yydefault;
  yyn = yytable[yyn];
  if (yyn <= 0)
    {
      if (yytable_value_is_error (yyn))
        goto yyerrlab;
      yyn = -yyn;
      goto yyreduce;
    }

  /* Count tokens shifted since error; after three, turn off error
     status.  */
  if (yyerrstatus)
    yyerrstatus--;

  /* Shift the lookahead token.  */
  YY_SYMBOL_PRINT ("Shifting", yytoken, &yylval, &yylloc);
  yystate = yyn;
  YY_IGNORE_MAYBE_UNINITIALIZED_BEGIN
  *++yyvsp = yylval;
  YY_IGNORE_MAYBE_UNINITIALIZED_END

  /* Discard the shifted token.  */
  yychar = INI_EMPTY;
  goto yynewstate;


/*-----------------------------------------------------------.
| yydefault -- do the default action for the current state.  |
`-----------------------------------------------------------*/
yydefault:
  yyn = yydefact[yystate];
  if (yyn == 0)
    goto yyerrlab;
  goto yyreduce;


/*-----------------------------.
| yyreduce -- do a reduction.  |
`-----------------------------*/
yyreduce:
  /* yyn is the number of a rule to reduce with.  */
  yylen = yyr2[yyn];

  /* If YYLEN is nonzero, implement the default value of the action:
     '$$ = $1'.

     Otherwise, the following line sets YYVAL to garbage.
     This behavior is undocumented and Bison
     users should not rely upon it.  Assigning to YYVAL
     unconditionally makes the parser a bit smaller, and it avoids a
     GCC warning that YYVAL may be used uninitialized.  */
  yyval = yyvsp[1-yylen];


  YY_REDUCE_PRINT (yyn);
  switch (yyn)
    {
  case 3: /* statement_list: %empty  */
#line 360 "/home/smamran09/php-src/Zend/zend_ini_parser.y"
                       { (void) ini_nerrs; }
#line 1927 "/home/smamran09/php-src/Zend/zend_ini_parser.c"
    break;

  case 4: /* statement: TC_SECTION section_string_or_value ']'  */
#line 364 "/home/smamran09/php-src/Zend/zend_ini_parser.y"
                                                       {
#if DEBUG_CFG_PARSER
			printf("SECTION: [%s]\n", Z_STRVAL(yyvsp[-1]));
#endif
			ZEND_INI_PARSER_CB(&yyvsp[-1], NULL, NULL, ZEND_INI_PARSER_SECTION, ZEND_INI_PARSER_ARG);
			zend_string_release(Z_STR(yyvsp[-1]));
		}
#line 1939 "/home/smamran09/php-src/Zend/zend_ini_parser.c"
    break;

  case 5: /* statement: TC_LABEL '=' string_or_value  */
#line 371 "/home/smamran09/php-src/Zend/zend_ini_parser.y"
                                             {
#if DEBUG_CFG_PARSER
			printf("NORMAL: '%s' = '%s'\n", Z_STRVAL(yyvsp[-2]), Z_STRVAL(yyvsp[0]));
#endif
			ZEND_INI_PARSER_CB(&yyvsp[-2], &yyvsp[0], NULL, ZEND_INI_PARSER_ENTRY, ZEND_INI_PARSER_ARG);
			if (ZEND_SYSTEM_INI) {
				GC_MAKE_PERSISTENT_LOCAL(Z_STR(yyvsp[-2]));
			}
			zend_string_release(Z_STR(yyvsp[-2]));
			zval_ini_dtor(&yyvsp[0]);
		}
#line 1955 "/home/smamran09/php-src/Zend/zend_ini_parser.c"
    break;

  case 6: /* statement: TC_OFFSET option_offset ']' '=' string_or_value  */
#line 382 "/home/smamran09/php-src/Zend/zend_ini_parser.y"
                                                                {
#if DEBUG_CFG_PARSER
			printf("OFFSET: '%s'[%s] = '%s'\n", Z_STRVAL(yyvsp[-4]), Z_STRVAL(yyvsp[-3]), Z_STRVAL(yyvsp[0]));
#endif
			ZEND_INI_PARSER_CB(&yyvsp[-4], &yyvsp[0], &yyvsp[-3], ZEND_INI_PARSER_POP_ENTRY, ZEND_INI_PARSER_ARG);
			zend_string_release(Z_STR(yyvsp[-4]));
			zval_ini_dtor(&yyvsp[-3]);
			zval_ini_dtor(&yyvsp[0]);
		}
#line 1969 "/home/smamran09/php-src/Zend/zend_ini_parser.c"
    break;

  case 7: /* statement: TC_LABEL  */
#line 391 "/home/smamran09/php-src/Zend/zend_ini_parser.y"
                                { ZEND_INI_PARSER_CB(&yyvsp[0], NULL, NULL, ZEND_INI_PARSER_ENTRY, ZEND_INI_PARSER_ARG); zend_string_release(Z_STR(yyvsp[0])); }
#line 1975 "/home/smamran09/php-src/Zend/zend_ini_parser.c"
    break;

  case 9: /* section_string_or_value: var_string_list_section  */
#line 396 "/home/smamran09/php-src/Zend/zend_ini_parser.y"
                                                        { yyval = yyvsp[0]; }
#line 1981 "/home/smamran09/php-src/Zend/zend_ini_parser.c"
    break;

  case 10: /* section_string_or_value: %empty  */
#line 397 "/home/smamran09/php-src/Zend/zend_ini_parser.y"
                                                                { zend_ini_init_string(&yyval); }
#line 1987 "/home/smamran09/php-src/Zend/zend_ini_parser.c"
    break;

  case 11: /* string_or_value: expr  */
#line 401 "/home/smamran09/php-src/Zend/zend_ini_parser.y"
                                                                        { yyval = yyvsp[0]; normalize_value(&yyval); }
#line 1993 "/home/smamran09/php-src/Zend/zend_ini_parser.c"
    break;

  case 12: /* string_or_value: BOOL_TRUE  */
#line 402 "/home/smamran09/php-src/Zend/zend_ini_parser.y"
                                                                        { yyval = yyvsp[0]; }
#line 1999 "/home/smamran09/php-src/Zend/zend_ini_parser.c"
    break;

  case 13: /* string_or_value: BOOL_FALSE  */
#line 403 "/home/smamran09/php-src/Zend/zend_ini_parser.y"
                                                                        { yyval = yyvsp[0]; }
#line 2005 "/home/smamran09/php-src/Zend/zend_ini_parser.c"
    break;

  case 14: /* string_or_value: NULL_NULL  */
#line 404 "/home/smamran09/php-src/Zend/zend_ini_parser.y"
                                                                        { yyval = yyvsp[0]; }
#line 2011 "/home/smamran09/php-src/Zend/zend_ini_parser.c"
    break;

  case 15: /* string_or_value: END_OF_LINE  */
#line 405 "/home/smamran09/php-src/Zend/zend_ini_parser.y"
                                                                        { zend_ini_init_string(&yyval); }
#line 2017 "/home/smamran09/php-src/Zend/zend_ini_parser.c"
    break;

  case 16: /* option_offset: var_string_list  */
#line 409 "/home/smamran09/php-src/Zend/zend_ini_parser.y"
                                                                { yyval = yyvsp[0]; }
#line 2023 "/home/smamran09/php-src/Zend/zend_ini_parser.c"
    break;

  case 17: /* option_offset: %empty  */
#line 410 "/home/smamran09/php-src/Zend/zend_ini_parser.y"
                                                                { zend_ini_init_string(&yyval); }
#line 2029 "/home/smamran09/php-src/Zend/zend_ini_parser.c"
    break;

  case 18: /* encapsed_list: encapsed_list cfg_var_ref  */
#line 414 "/home/smamran09/php-src/Zend/zend_ini_parser.y"
                                                        { zend_ini_add_string(&yyval, &yyvsp[-1], &yyvsp[0]); zend_string_free(Z_STR(yyvsp[0])); }
#line 2035 "/home/smamran09/php-src/Zend/zend_ini_parser.c"
    break;

  case 19: /* encapsed_list: encapsed_list TC_QUOTED_STRING  */
#line 415 "/home/smamran09/php-src/Zend/zend_ini_parser.y"
                                                { zend_ini_add_string(&yyval, &yyvsp[-1], &yyvsp[0]); zend_string_free(Z_STR(yyvsp[0])); }
#line 2041 "/home/smamran09/php-src/Zend/zend_ini_parser.c"
    break;

  case 20: /* encapsed_list: %empty  */
#line 416 "/home/smamran09/php-src/Zend/zend_ini_parser.y"
                                                                { zend_ini_init_string(&yyval); }
#line 2047 "/home/smamran09/php-src/Zend/zend_ini_parser.c"
    break;

  case 21: /* var_string_list_section: cfg_var_ref  */
#line 420 "/home/smamran09/php-src/Zend/zend_ini_parser.y"
                                                                        { yyval = yyvsp[0]; }
#line 2053 "/home/smamran09/php-src/Zend/zend_ini_parser.c"
    break;

  case 22: /* var_string_list_section: constant_literal  */
#line 421 "/home/smamran09/php-src/Zend/zend_ini_parser.y"
                                                                { yyval = yyvsp[0]; }
#line 2059 "/home/smamran09/php-src/Zend/zend_ini_parser.c"
    break;

  case 23: /* var_string_list_section: '"' encapsed_list '"'  */
#line 422 "/home/smamran09/php-src/Zend/zend_ini_parser.y"
                                                        { yyval = yyvsp[-1]; }
#line 2065 "/home/smamran09/php-src/Zend/zend_ini_parser.c"
    break;

  case 24: /* var_string_list_section: var_string_list_section cfg_var_ref  */
#line 423 "/home/smamran09/php-src/Zend/zend_ini_parser.y"
                                                        { zend_ini_add_string(&yyval, &yyvsp[-1], &yyvsp[0]); zend_string_free(Z_STR(yyvsp[0])); }
#line 2071 "/home/smamran09/php-src/Zend/zend_ini_parser.c"
    break;

  case 25: /* var_string_list_section: var_string_list_section constant_literal  */
#line 424 "/home/smamran09/php-src/Zend/zend_ini_parser.y"
                                                                { zend_ini_add_string(&yyval, &yyvsp[-1], &yyvsp[0]); zend_string_free(Z_STR(yyvsp[0])); }
#line 2077 "/home/smamran09/php-src/Zend/zend_ini_parser.c"
    break;

  case 26: /* var_string_list_section: var_string_list_section '"' encapsed_list '"'  */
#line 425 "/home/smamran09/php-src/Zend/zend_ini_parser.y"
                                                               { zend_ini_add_string(&yyval, &yyvsp[-3], &yyvsp[-1]); zend_string_free(Z_STR(yyvsp[-1])); }
#line 2083 "/home/smamran09/php-src/Zend/zend_ini_parser.c"
    break;

  case 27: /* var_string_list: cfg_var_ref  */
#line 429 "/home/smamran09/php-src/Zend/zend_ini_parser.y"
                                                                        { yyval = yyvsp[0]; }
#line 2089 "/home/smamran09/php-src/Zend/zend_ini_parser.c"
    break;

  case 28: /* var_string_list: constant_string  */
#line 430 "/home/smamran09/php-src/Zend/zend_ini_parser.y"
                                                                { yyval = yyvsp[0]; }
#line 2095 "/home/smamran09/php-src/Zend/zend_ini_parser.c"
    break;

  case 29: /* var_string_list: '"' encapsed_list '"'  */
#line 431 "/home/smamran09/php-src/Zend/zend_ini_parser.y"
                                                        { yyval = yyvsp[-1]; }
#line 2101 "/home/smamran09/php-src/Zend/zend_ini_parser.c"
    break;

  case 30: /* var_string_list: var_string_list cfg_var_ref  */
#line 432 "/home/smamran09/php-src/Zend/zend_ini_parser.y"
                                                { zend_ini_add_string(&yyval, &yyvsp[-1], &yyvsp[0]); zend_string_free(Z_STR(yyvsp[0])); }
#line 2107 "/home/smamran09/php-src/Zend/zend_ini_parser.c"
    break;

  case 31: /* var_string_list: var_string_list constant_string  */
#line 433 "/home/smamran09/php-src/Zend/zend_ini_parser.y"
                                                { zend_ini_add_string(&yyval, &yyvsp[-1], &yyvsp[0]); zend_string_free(Z_STR(yyvsp[0])); }
#line 2113 "/home/smamran09/php-src/Zend/zend_ini_parser.c"
    break;

  case 32: /* var_string_list: var_string_list '"' encapsed_list '"'  */
#line 434 "/home/smamran09/php-src/Zend/zend_ini_parser.y"
                                                       { zend_ini_add_string(&yyval, &yyvsp[-3], &yyvsp[-1]); zend_string_free(Z_STR(yyvsp[-1])); }
#line 2119 "/home/smamran09/php-src/Zend/zend_ini_parser.c"
    break;

  case 33: /* expr: var_string_list  */
#line 438 "/home/smamran09/php-src/Zend/zend_ini_parser.y"
                                                                { yyval = yyvsp[0]; }
#line 2125 "/home/smamran09/php-src/Zend/zend_ini_parser.c"
    break;

  case 34: /* expr: expr '|' expr  */
#line 439 "/home/smamran09/php-src/Zend/zend_ini_parser.y"
                                                                { zend_ini_do_op('|', &yyval, &yyvsp[-2], &yyvsp[0]); }
#line 2131 "/home/smamran09/php-src/Zend/zend_ini_parser.c"
    break;

  case 35: /* expr: expr '&' expr  */
#line 440 "/home/smamran09/php-src/Zend/zend_ini_parser.y"
                                                                { zend_ini_do_op('&', &yyval, &yyvsp[-2], &yyvsp[0]); }
#line 2137 "/home/smamran09/php-src/Zend/zend_ini_parser.c"
    break;

  case 36: /* expr: expr '^' expr  */
#line 441 "/home/smamran09/php-src/Zend/zend_ini_parser.y"
                                                                { zend_ini_do_op('^', &yyval, &yyvsp[-2], &yyvsp[0]); }
#line 2143 "/home/smamran09/php-src/Zend/zend_ini_parser.c"
    break;

  case 37: /* expr: '~' expr  */
#line 442 "/home/smamran09/php-src/Zend/zend_ini_parser.y"
                                                                        { zend_ini_do_op('~', &yyval, &yyvsp[0], NULL); }
#line 2149 "/home/smamran09/php-src/Zend/zend_ini_parser.c"
    break;

  case 38: /* expr: '!' expr  */
#line 443 "/home/smamran09/php-src/Zend/zend_ini_parser.y"
                                                                        { zend_ini_do_op('!', &yyval, &yyvsp[0], NULL); }
#line 2155 "/home/smamran09/php-src/Zend/zend_ini_parser.c"
    break;

  case 39: /* expr: '(' expr ')'  */
#line 444 "/home/smamran09/php-src/Zend/zend_ini_parser.y"
                                                                { yyval = yyvsp[-1]; }
#line 2161 "/home/smamran09/php-src/Zend/zend_ini_parser.c"
    break;

  case 40: /* cfg_var_ref: TC_DOLLAR_CURLY TC_VARNAME '}'  */
#line 448 "/home/smamran09/php-src/Zend/zend_ini_parser.y"
                                                                        { zend_ini_get_var(&yyval, &yyvsp[-1], NULL); zend_string_free(Z_STR(yyvsp[-1])); }
#line 2167 "/home/smamran09/php-src/Zend/zend_ini_parser.c"
    break;

  case 41: /* cfg_var_ref: TC_DOLLAR_CURLY TC_VARNAME TC_FALLBACK fallback '}'  */
#line 449 "/home/smamran09/php-src/Zend/zend_ini_parser.y"
                                                                        { zend_ini_get_var(&yyval, &yyvsp[-3], &yyvsp[-1]); zend_string_free(Z_STR(yyvsp[-3])); zend_string_free(Z_STR(yyvsp[-1])); }
#line 2173 "/home/smamran09/php-src/Zend/zend_ini_parser.c"
    break;

  case 42: /* fallback: var_string_list  */
#line 454 "/home/smamran09/php-src/Zend/zend_ini_parser.y"
                                { yyval = yyvsp[0]; }
#line 2179 "/home/smamran09/php-src/Zend/zend_ini_parser.c"
    break;

  case 43: /* fallback: %empty  */
#line 455 "/home/smamran09/php-src/Zend/zend_ini_parser.y"
                                        { zend_ini_init_string(&yyval); }
#line 2185 "/home/smamran09/php-src/Zend/zend_ini_parser.c"
    break;

  case 44: /* constant_literal: TC_CONSTANT  */
#line 459 "/home/smamran09/php-src/Zend/zend_ini_parser.y"
                                                                        { yyval = yyvsp[0]; }
#line 2191 "/home/smamran09/php-src/Zend/zend_ini_parser.c"
    break;

  case 45: /* constant_literal: TC_RAW  */
#line 460 "/home/smamran09/php-src/Zend/zend_ini_parser.y"
                                                                        { yyval = yyvsp[0]; /*printf("TC_RAW: '%s'\n", Z_STRVAL($1));*/ }
#line 2197 "/home/smamran09/php-src/Zend/zend_ini_parser.c"
    break;

  case 46: /* constant_literal: TC_NUMBER  */
#line 461 "/home/smamran09/php-src/Zend/zend_ini_parser.y"
                                                                        { yyval = yyvsp[0]; /*printf("TC_NUMBER: '%s'\n", Z_STRVAL($1));*/ }
#line 2203 "/home/smamran09/php-src/Zend/zend_ini_parser.c"
    break;

  case 47: /* constant_literal: TC_STRING  */
#line 462 "/home/smamran09/php-src/Zend/zend_ini_parser.y"
                                                                        { yyval = yyvsp[0]; /*printf("TC_STRING: '%s'\n", Z_STRVAL($1));*/ }
#line 2209 "/home/smamran09/php-src/Zend/zend_ini_parser.c"
    break;

  case 48: /* constant_literal: TC_WHITESPACE  */
#line 463 "/home/smamran09/php-src/Zend/zend_ini_parser.y"
                                                                { yyval = yyvsp[0]; /*printf("TC_WHITESPACE: '%s'\n", Z_STRVAL($1));*/ }
#line 2215 "/home/smamran09/php-src/Zend/zend_ini_parser.c"
    break;

  case 49: /* constant_string: TC_CONSTANT  */
#line 467 "/home/smamran09/php-src/Zend/zend_ini_parser.y"
                                                                        { zend_ini_get_constant(&yyval, &yyvsp[0]); }
#line 2221 "/home/smamran09/php-src/Zend/zend_ini_parser.c"
    break;

  case 50: /* constant_string: TC_RAW  */
#line 468 "/home/smamran09/php-src/Zend/zend_ini_parser.y"
                                                                        { yyval = yyvsp[0]; /*printf("TC_RAW: '%s'\n", Z_STRVAL($1));*/ }
#line 2227 "/home/smamran09/php-src/Zend/zend_ini_parser.c"
    break;

  case 51: /* constant_string: TC_NUMBER  */
#line 469 "/home/smamran09/php-src/Zend/zend_ini_parser.y"
                          {
			yyval = yyvsp[0];
			Z_EXTRA(yyval) = INI_ZVAL_IS_NUMBER;
			/*printf("TC_NUMBER: '%s'\n", Z_STRVAL($1));*/
		}
#line 2237 "/home/smamran09/php-src/Zend/zend_ini_parser.c"
    break;

  case 52: /* constant_string: TC_STRING  */
#line 474 "/home/smamran09/php-src/Zend/zend_ini_parser.y"
                                                                        { yyval = yyvsp[0]; /*printf("TC_STRING: '%s'\n", Z_STRVAL($1));*/ }
#line 2243 "/home/smamran09/php-src/Zend/zend_ini_parser.c"
    break;

  case 53: /* constant_string: TC_WHITESPACE  */
#line 475 "/home/smamran09/php-src/Zend/zend_ini_parser.y"
                                                                { yyval = yyvsp[0]; /*printf("TC_WHITESPACE: '%s'\n", Z_STRVAL($1));*/ }
#line 2249 "/home/smamran09/php-src/Zend/zend_ini_parser.c"
    break;


#line 2253 "/home/smamran09/php-src/Zend/zend_ini_parser.c"

      default: break;
    }
  /* User semantic actions sometimes alter yychar, and that requires
     that yytoken be updated with the new translation.  We take the
     approach of translating immediately before every use of yytoken.
     One alternative is translating here after every semantic action,
     but that translation would be missed if the semantic action invokes
     YYABORT, YYACCEPT, or YYERROR immediately after altering yychar or
     if it invokes YYBACKUP.  In the case of YYABORT or YYACCEPT, an
     incorrect destructor might then be invoked immediately.  In the
     case of YYERROR or YYBACKUP, subsequent parser actions might lead
     to an incorrect destructor call or verbose syntax error message
     before the lookahead is translated.  */
  YY_SYMBOL_PRINT ("-> $$ =", YY_CAST (yysymbol_kind_t, yyr1[yyn]), &yyval, &yyloc);

  YYPOPSTACK (yylen);
  yylen = 0;

  *++yyvsp = yyval;

  /* Now 'shift' the result of the reduction.  Determine what state
     that goes to, based on the state we popped back to and the rule
     number reduced by.  */
  {
    const int yylhs = yyr1[yyn] - YYNTOKENS;
    const int yyi = yypgoto[yylhs] + *yyssp;
    yystate = (0 <= yyi && yyi <= YYLAST && yycheck[yyi] == *yyssp
               ? yytable[yyi]
               : yydefgoto[yylhs]);
  }

  goto yynewstate;


/*--------------------------------------.
| yyerrlab -- here on detecting error.  |
`--------------------------------------*/
yyerrlab:
  /* Make sure we have latest lookahead translation.  See comments at
     user semantic actions for why this is necessary.  */
  yytoken = yychar == INI_EMPTY ? YYSYMBOL_YYEMPTY : YYTRANSLATE (yychar);
  /* If not already recovering from an error, report this error.  */
  if (!yyerrstatus)
    {
      ++yynerrs;
      {
        yypcontext_t yyctx
          = {yyssp, yytoken};
        char const *yymsgp = YY_("syntax error");
        int yysyntax_error_status;
        yysyntax_error_status = yysyntax_error (&yymsg_alloc, &yymsg, &yyctx);
        if (yysyntax_error_status == 0)
          yymsgp = yymsg;
        else if (yysyntax_error_status == -1)
          {
            if (yymsg != yymsgbuf)
              YYSTACK_FREE (yymsg);
            yymsg = YY_CAST (char *,
                             YYSTACK_ALLOC (YY_CAST (YYSIZE_T, yymsg_alloc)));
            if (yymsg)
              {
                yysyntax_error_status
                  = yysyntax_error (&yymsg_alloc, &yymsg, &yyctx);
                yymsgp = yymsg;
              }
            else
              {
                yymsg = yymsgbuf;
                yymsg_alloc = sizeof yymsgbuf;
                yysyntax_error_status = YYENOMEM;
              }
          }
        yyerror (yymsgp);
        if (yysyntax_error_status == YYENOMEM)
          goto yyexhaustedlab;
      }
    }

  if (yyerrstatus == 3)
    {
      /* If just tried and failed to reuse lookahead token after an
         error, discard it.  */

      if (yychar <= END)
        {
          /* Return failure if at end of input.  */
          if (yychar == END)
            YYABORT;
        }
      else
        {
          yydestruct ("Error: discarding",
                      yytoken, &yylval);
          yychar = INI_EMPTY;
        }
    }

  /* Else will try to reuse lookahead token after shifting the error
     token.  */
  goto yyerrlab1;


/*---------------------------------------------------.
| yyerrorlab -- error raised explicitly by YYERROR.  |
`---------------------------------------------------*/
yyerrorlab:
  /* Pacify compilers when the user code never invokes YYERROR and the
     label yyerrorlab therefore never appears in user code.  */
  if (0)
    YYERROR;

  /* Do not reclaim the symbols of the rule whose action triggered
     this YYERROR.  */
  YYPOPSTACK (yylen);
  yylen = 0;
  YY_STACK_PRINT (yyss, yyssp);
  yystate = *yyssp;
  goto yyerrlab1;


/*-------------------------------------------------------------.
| yyerrlab1 -- common code for both syntax error and YYERROR.  |
`-------------------------------------------------------------*/
yyerrlab1:
  yyerrstatus = 3;      /* Each real token shifted decrements this.  */

  /* Pop stack until we find a state that shifts the error token.  */
  for (;;)
    {
      yyn = yypact[yystate];
      if (!yypact_value_is_default (yyn))
        {
          yyn += YYSYMBOL_YYerror;
          if (0 <= yyn && yyn <= YYLAST && yycheck[yyn] == YYSYMBOL_YYerror)
            {
              yyn = yytable[yyn];
              if (0 < yyn)
                break;
            }
        }

      /* Pop the current state because it cannot handle the error token.  */
      if (yyssp == yyss)
        YYABORT;


      yydestruct ("Error: popping",
                  YY_ACCESSING_SYMBOL (yystate), yyvsp);
      YYPOPSTACK (1);
      yystate = *yyssp;
      YY_STACK_PRINT (yyss, yyssp);
    }

  YY_IGNORE_MAYBE_UNINITIALIZED_BEGIN
  *++yyvsp = yylval;
  YY_IGNORE_MAYBE_UNINITIALIZED_END


  /* Shift the error token.  */
  YY_SYMBOL_PRINT ("Shifting", YY_ACCESSING_SYMBOL (yyn), yyvsp, yylsp);

  yystate = yyn;
  goto yynewstate;


/*-------------------------------------.
| yyacceptlab -- YYACCEPT comes here.  |
`-------------------------------------*/
yyacceptlab:
  yyresult = 0;
  goto yyreturn;


/*-----------------------------------.
| yyabortlab -- YYABORT comes here.  |
`-----------------------------------*/
yyabortlab:
  yyresult = 1;
  goto yyreturn;


#if 1
/*-------------------------------------------------.
| yyexhaustedlab -- memory exhaustion comes here.  |
`-------------------------------------------------*/
yyexhaustedlab:
  yyerror (YY_("memory exhausted"));
  yyresult = 2;
  goto yyreturn;
#endif


/*-------------------------------------------------------.
| yyreturn -- parsing is finished, clean up and return.  |
`-------------------------------------------------------*/
yyreturn:
  if (yychar != INI_EMPTY)
    {
      /* Make sure we have latest lookahead translation.  See comments at
         user semantic actions for why this is necessary.  */
      yytoken = YYTRANSLATE (yychar);
      yydestruct ("Cleanup: discarding lookahead",
                  yytoken, &yylval);
    }
  /* Do not reclaim the symbols of the rule whose action triggered
     this YYABORT or YYACCEPT.  */
  YYPOPSTACK (yylen);
  YY_STACK_PRINT (yyss, yyssp);
  while (yyssp != yyss)
    {
      yydestruct ("Cleanup: popping",
                  YY_ACCESSING_SYMBOL (+*yyssp), yyvsp);
      YYPOPSTACK (1);
    }
#ifndef yyoverflow
  if (yyss != yyssa)
    YYSTACK_FREE (yyss);
#endif
  if (yymsg != yymsgbuf)
    YYSTACK_FREE (yymsg);
  return yyresult;
}

