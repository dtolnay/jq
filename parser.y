%{
#include <assert.h>
#include <math.h>
#include <stdio.h>
#include <string.h>
#include "ast.h"
#include "compile.h"
#include "jv_alloc.h"
#define YYMALLOC jv_mem_alloc
#define YYFREE jv_mem_free
%}
%code requires {
#include "ast.h"
#include "locfile.h"
struct lexer_param;

#define YYLTYPE location
#define YYLLOC_DEFAULT(Loc, Rhs, N)             \
  do {                                          \
    if (N) {                                    \
      (Loc).start = YYRHSLOC(Rhs, 1).start;     \
      (Loc).end = YYRHSLOC(Rhs, N).end;         \
    } else {                                    \
      (Loc).start = YYRHSLOC(Rhs, 0).end;       \
      (Loc).end = YYRHSLOC(Rhs, 0).end;         \
    }                                           \
  } while (0)
}

%locations
%error-verbose
%define api.pure
%union {
  jv literal;
  ast_node *node;
}

%destructor { jv_free($$); } <literal>
%destructor { ast_free($$); } <node>

%parse-param {ast_node **answer}
%parse-param {int* errors}
%parse-param {struct locfile* locations}
%parse-param {struct lexer_param* lexer_param_ptr}
%lex-param {ast_node **answer}
%lex-param {int* errors}
%lex-param {struct locfile* locations}
%lex-param {struct lexer_param* lexer_param_ptr}


%token INVALID_CHARACTER
%token <literal> IDENT
%token <literal> FIELD
%token <literal> LITERAL
%token <literal> FORMAT
%token REC ".."
%token SETMOD "%="
%token EQ "=="
%token NEQ "!="
%token DEFINEDOR "//"
%token AS "as"
%token DEF "def"
%token MODULE "module"
%token IMPORT "import"
%token INCLUDE "include"
%token IF "if"
%token THEN "then"
%token ELSE "else"
%token ELSE_IF "elif"
%token REDUCE "reduce"
%token FOREACH "foreach"
%token END "end"
%token AND "and"
%token OR "or"
%token TRY "try"
%token CATCH "catch"
%token LABEL "label"
%token BREAK "break"
%token LOC "__loc__"
%token SETPIPE "|="
%token SETPLUS "+="
%token SETMINUS "-="
%token SETMULT "*="
%token SETDIV "/="
%token SETDEFINEDOR "//="
%token LESSEQ "<="
%token GREATEREQ ">="

%token QQSTRING_START
%token <literal> QQSTRING_TEXT
%token QQSTRING_INTERP_START
%token QQSTRING_INTERP_END
%token QQSTRING_END

/* Instead of raising this, find a way to use precedence to resolve
 * shift-reduce conflicts. */
%expect 0

%precedence FUNCDEF
%right '|'
%left ','
%right "//"
%nonassoc '=' SETPIPE SETPLUS SETMINUS SETMULT SETDIV SETMOD SETDEFINEDOR
%left OR
%left AND
%nonassoc NEQ EQ '<' '>' LESSEQ GREATEREQ
%left '+' '-'
%left '*' '/' '%'
%precedence NONOPT /* non-optional; rules for which a specialized
                      '?' rule should be preferred over Exp '?' */
%precedence '?'
%precedence "try"
%precedence "catch"


%type <node> Exp Term
%type <node> MkDict MkDictPair ExpD
%type <node> ElseBody
%type <node> String QQString
%type <node> FuncDef FuncDefs
%type <node> Module Import Imports ImportWhat ImportFrom
%type <node> Param Params Arg Args
%type <node> Pattern ArrayPats ObjPats ObjPat
%type <literal> Keyword
%{
#include "lexer.h"
struct lexer_param {
  yyscan_t lexer;
};
#define FAIL(loc, msg)                                             \
  do {                                                             \
    location l = loc;                                              \
    yyerror(&l, answer, errors, locations, lexer_param_ptr, msg);  \
    /*YYERROR*/;                                                   \
  } while (0)

void yyerror(YYLTYPE* loc, ast_node** answer, int* errors,
             struct locfile* locations, struct lexer_param* lexer_param_ptr, const char *s){
  (*errors)++;
  if (strstr(s, "unexpected")) {
#ifdef WIN32
      locfile_locate(locations, *loc, "jq: error: %s (Windows cmd shell quoting issues?)", s);
#else
      locfile_locate(locations, *loc, "jq: error: %s (Unix shell quoting issues?)", s);
#endif
  } else {
      locfile_locate(locations, *loc, "jq: error: %s", s);
  }
}

int yylex(YYSTYPE* yylval, YYLTYPE* yylloc, ast_node** answer, int* errors,
          struct locfile* locations, struct lexer_param* lexer_param_ptr) {
  yyscan_t lexer = lexer_param_ptr->lexer;
  int tok = jq_yylex(yylval, yylloc, lexer);
  if ((tok == LITERAL || tok == QQSTRING_TEXT) && !jv_is_valid(yylval->literal)) {
    jv msg = jv_invalid_get_msg(jv_copy(yylval->literal));
    if (jv_get_kind(msg) == JV_KIND_STRING) {
      FAIL(*yylloc, jv_string_value(msg));
    } else {
      FAIL(*yylloc, "Invalid literal");
    }
    jv_free(msg);
    jv_free(yylval->literal);
    yylval->literal = jv_null();
  }
  return tok;
}

static ast_node *gen_dictpair(ast_node *k, ast_node *v) {
  return ast_todo(BLOCK(gen_subexp(ast_block(k)), gen_subexp(ast_block(v)), gen_op_simple(INSERT)));
}

static block gen_slice_index(block obj, block start, block end, opcode idx_op) {
  block key = BLOCK(gen_subexp(gen_const(jv_object())),
                    gen_subexp(gen_const(jv_string("start"))),
                    gen_subexp(start),
                    gen_op_simple(INSERT),
                    gen_subexp(gen_const(jv_string("end"))),
                    gen_subexp(end),
                    gen_op_simple(INSERT));
  return BLOCK(key, obj, gen_op_simple(idx_op));
}

static block constant_fold(block a, block b, int op) {
  if (!block_is_single(a) || !block_is_const(a) ||
      !block_is_single(b) || !block_is_const(b))
    return gen_noop();
  if (op == '+') {
    if (block_const_kind(a) == JV_KIND_NULL) {
      block_free(a);
      return b;
    }
    if (block_const_kind(b) == JV_KIND_NULL) {
      block_free(b);
      return a;
    }
  }
  if (block_const_kind(a) != block_const_kind(b))
    return gen_noop();

  jv res = jv_invalid();

  if (block_const_kind(a) == JV_KIND_NUMBER) {
    double na = jv_number_value(block_const(a));
    double nb = jv_number_value(block_const(b));
    switch (op) {
    case '+': res = jv_number(na + nb); break;
    case '-': res = jv_number(na - nb); break;
    case '*': res = jv_number(na * nb); break;
    case '/': res = jv_number(na / nb); break;
    case EQ:  res = (na == nb ? jv_true() : jv_false()); break;
    case NEQ: res = (na != nb ? jv_true() : jv_false()); break;
    case '<': res = (na < nb ? jv_true() : jv_false()); break;
    case '>': res = (na > nb ? jv_true() : jv_false()); break;
    case LESSEQ: res = (na <= nb ? jv_true() : jv_false()); break;
    case GREATEREQ: res = (na >= nb ? jv_true() : jv_false()); break;
    default: break;
    }
  } else if (op == '+' && block_const_kind(a) == JV_KIND_STRING) {
    res = jv_string_concat(block_const(a),  block_const(b));
  } else {
    return gen_noop();
  }

  if (jv_get_kind(res) == JV_KIND_INVALID)
    return gen_noop();

  block_free(a);
  block_free(b);
  return gen_const(res);
}

static ast_node *gen_binop(ast_node *a, ast_node *b, int op) {
  block aa = ast_block(a);
  block bb = ast_block(b);
  block folded = constant_fold(aa, bb, op);
  if (!block_is_noop(folded))
    return ast_todo(folded);

  const char* funcname = 0;
  switch (op) {
  case '+': funcname = "_plus"; break;
  case '-': funcname = "_minus"; break;
  case '*': funcname = "_multiply"; break;
  case '/': funcname = "_divide"; break;
  case '%': funcname = "_mod"; break;
  case EQ: funcname = "_equal"; break;
  case NEQ: funcname = "_notequal"; break;
  case '<': funcname = "_less"; break;
  case '>': funcname = "_greater"; break;
  case LESSEQ: funcname = "_lesseq"; break;
  case GREATEREQ: funcname = "_greatereq"; break;
  }
  assert(funcname);

  return ast_todo(gen_call(funcname, BLOCK(gen_lambda(aa), gen_lambda(bb))));
}

static ast_node *gen_format(ast_node *a, jv fmt) {
  return ast_todo(BLOCK(ast_block(a), gen_call("format", gen_lambda(gen_const(fmt)))));
}

static ast_node *gen_definedor_assign(ast_node *object, ast_node *val) {
  block tmp = gen_op_var_fresh(STOREV, "tmp");
  return ast_todo(BLOCK(gen_op_simple(DUP),
               ast_block(val), tmp,
               gen_call("_modify", BLOCK(gen_lambda(ast_block(object)),
                                         gen_lambda(gen_definedor(gen_noop(),
                                                                  gen_op_bound(LOADV, tmp)))))));
}

static ast_node *gen_update(ast_node *object, ast_node *val, int optype) {
  block tmp = gen_op_var_fresh(STOREV, "tmp");
  return ast_todo(BLOCK(gen_op_simple(DUP),
               ast_block(val),
               tmp,
               gen_call("_modify", BLOCK(gen_lambda(ast_block(object)),
                                         gen_lambda(ast_block(gen_binop(ast_todo(gen_noop()),
                                                              ast_todo(gen_op_bound(LOADV, tmp)),
                                                              optype)))))));
}

%}

%%
TopLevel:
Module Imports Exp {
  *answer = ast_mk_top($1, $2, $3);
} |
Module Imports FuncDefs {
  *answer = ast_todo(BLOCK(ast_block($1), ast_block($2), ast_block($3)));
}

Module:
%empty {
  $$ = NULL;
} |
"module" Exp ';' {
  block name = ast_block($2);
  if (!block_is_const(name)) {
    FAIL(@$, "Module metadata must be constant.");
    $$ = NULL;
    block_free(name);
  } else {
    $$ = ast_todo(gen_module(name));
  }
}

Imports:
%empty {
  $$ = NULL;
} |
Import Imports {
  $$ = ast_todo(BLOCK(ast_block($1), ast_block($2)));
}

FuncDefs:
%empty {
  $$ = NULL;
} |
FuncDef FuncDefs {
  $$ = ast_todo(block_bind(ast_block($1), ast_block($2), OP_IS_CALL_PSEUDO));
}

Exp:
FuncDef Exp %prec FUNCDEF {
  $$ = ast_todo(block_bind_referenced(ast_block($1), ast_block($2), OP_IS_CALL_PSEUDO));
} |

Term "as" Pattern '|' Exp {
  $$ = ast_todo(gen_destructure(ast_block($1), ast_block($3), ast_block($5)));
} |

"reduce" Term "as" Pattern '(' Exp ';' Exp ')' {
  $$ = ast_todo(gen_reduce(ast_block($2), ast_block($4), ast_block($6), ast_block($8)));
} |

"foreach" Term "as" Pattern '(' Exp ';' Exp ';' Exp ')' {
  $$ = ast_todo(gen_foreach(ast_block($2), ast_block($4), ast_block($6), ast_block($8), ast_block($10)));
} |

"foreach" Term "as" Pattern '(' Exp ';' Exp ')' {
  $$ = ast_todo(gen_foreach(ast_block($2), ast_block($4), ast_block($6), ast_block($8), gen_noop()));
} |

"if" Exp "then" Exp ElseBody {
  $$ = ast_todo(gen_cond(ast_block($2), ast_block($4), ast_block($5)));
} |
"if" Exp "then" error {
  FAIL(@$, "Possibly unterminated 'if' statement");
  $$ = $2;
} |

"try" Exp "catch" Exp {
  //$$ = BLOCK(gen_op_target(FORK_OPT, $2), $2, $4);
  $$ = ast_todo(gen_try(ast_block($2), gen_try_handler(ast_block($4))));
} |
"try" Exp {
  //$$ = BLOCK(gen_op_target(FORK_OPT, $2), $2, gen_op_simple(BACKTRACK));
  $$ = ast_todo(gen_try(ast_block($2), gen_op_simple(BACKTRACK)));
} |
"try" Exp "catch" error {
  FAIL(@$, "Possibly unterminated 'try' statement");
  $$ = $2;
} |

"label" '$' IDENT '|' Exp {
  jv v = jv_string_fmt("*label-%s", jv_string_value($3));
  $$ = ast_todo(gen_location(@$, locations, gen_label(jv_string_value(v), ast_block($5))));
  jv_free($3);
  jv_free(v);
} |

Exp '?' {
  $$ = ast_todo(gen_try(ast_block($1), gen_op_simple(BACKTRACK)));
} |

Exp '=' Exp {
  $$ = ast_todo(gen_call("_assign", BLOCK(gen_lambda(ast_block($1)), gen_lambda(ast_block($3)))));
} |

Exp "or" Exp {
  $$ = ast_todo(gen_or(ast_block($1), ast_block($3)));
} |

Exp "and" Exp {
  $$ = ast_todo(gen_and(ast_block($1), ast_block($3)));
} |

Exp "//" Exp {
  $$ = ast_todo(gen_definedor(ast_block($1), ast_block($3)));
} |

Exp "//=" Exp {
  $$ = gen_definedor_assign($1, $3);
} |

Exp "|=" Exp {
  $$ = ast_todo(gen_call("_modify", BLOCK(gen_lambda(ast_block($1)), gen_lambda(ast_block($3)))));
} |

Exp '|' Exp {
  $$ = ast_mk_compose($1, $3);
} |

Exp ',' Exp {
  $$ = ast_mk_both($1, $3);
} |

Exp '+' Exp {
  $$ = ast_mk_binop($1, $3, AST_PLUS);
} |

Exp "+=" Exp {
  $$ = gen_update($1, $3, '+');
} |

'-' Exp {
  $$ = ast_todo(BLOCK(ast_block($2), gen_call("_negate", gen_noop())));
} |

Exp '-' Exp {
  $$ = ast_mk_binop($1, $3, AST_MINUS);
} |

Exp "-=" Exp {
  $$ = gen_update($1, $3, '-');
} |

Exp '*' Exp {
  $$ = ast_mk_binop($1, $3, AST_TIMES);
} |

Exp "*=" Exp {
  $$ = gen_update($1, $3, '*');
} |

Exp '/' Exp {
  block val = ast_block(gen_binop($1, $3, '/'));
  if (block_is_const_inf(val))
    FAIL(@$, "Division by zero?");
  $$ = ast_todo(val);
} |

Exp '%' Exp {
  block val = ast_block(gen_binop($1, $3, '%'));
  if (block_is_const_inf(val))
    FAIL(@$, "Remainder by zero?");
  $$ = ast_todo(val);
} |

Exp "/=" Exp {
  $$ = gen_update($1, $3, '/');
} |

Exp SETMOD Exp {
  $$ = gen_update($1, $3, '%');
} |

Exp "==" Exp {
  $$ = gen_binop($1, $3, EQ);
} |

Exp "!=" Exp {
  $$ = gen_binop($1, $3, NEQ);
} |

Exp '<' Exp {
  $$ = gen_binop($1, $3, '<');
} |

Exp '>' Exp {
  $$ = gen_binop($1, $3, '>');
} |

Exp "<=" Exp {
  $$ = gen_binop($1, $3, LESSEQ);
} |

Exp ">=" Exp {
  $$ = gen_binop($1, $3, GREATEREQ);
} |

Term {
  $$ = $1;
}

Import:
ImportWhat ';' {
  $$ = $1;
} |
ImportWhat Exp ';' {
  block source = ast_block($1);
  block meta = ast_block($2);
  if (!block_is_const(meta)) {
    FAIL(@$, "Module metadata must be constant");
    $$ = ast_todo(gen_noop());
    block_free(source);
    block_free(meta);
  } else if (block_const_kind(meta) != JV_KIND_OBJECT) {
    FAIL(@$, "Module metadata must be an object");
    $$ = ast_todo(gen_noop());
    block_free(source);
    block_free(meta);
  } else {
    $$ = ast_todo(gen_import_meta(source, meta));
  }
}

ImportWhat:
"import" ImportFrom "as" '$' IDENT {
  block source = ast_block($2);
  jv v = block_const(source);
  // XXX Make gen_import take only blocks and the int is_data so we
  // don't have to free so much stuff here
  $$ = ast_todo(gen_import(jv_string_value(v), jv_string_value($5), 1));
  block_free(source);
  jv_free($5);
  jv_free(v);
} |
"import" ImportFrom "as" IDENT {
  block source = ast_block($2);
  jv v = block_const(source);
  $$ = ast_todo(gen_import(jv_string_value(v), jv_string_value($4), 0));
  block_free(source);
  jv_free($4);
  jv_free(v);
} |
"include" ImportFrom {
  block source = ast_block($2);
  jv v = block_const(source);
  $$ = ast_todo(gen_import(jv_string_value(v), NULL, 0));
  block_free(source);
  jv_free(v);
}

ImportFrom:
String {
  block source = ast_block($1);
  if (!block_is_const(source)) {
    FAIL(@$, "Import path must be constant");
    $$ = ast_mk_const(jv_string(""));
    block_free(source);
  } else {
    $$ = ast_todo(source);
  }
}

FuncDef:
"def" IDENT ':' Exp ';' {
  $$ = ast_todo(gen_function(jv_string_value($2), gen_noop(), ast_block($4)));
  jv_free($2);
} |

"def" IDENT '(' Params ')' ':' Exp ';' {
  $$ = ast_todo(gen_function(jv_string_value($2), ast_block($4), ast_block($7)));
  jv_free($2);
}

Params:
Param {
  $$ = $1;
} |
Params ';' Param {
  $$ = ast_todo(BLOCK(ast_block($1), ast_block($3)));
}

Param:
'$' IDENT {
  $$ = ast_todo(gen_param_regular(jv_string_value($2)));
  jv_free($2);
} |

IDENT {
  $$ = ast_todo(gen_param(jv_string_value($1)));
  jv_free($1);
}


String:
QQSTRING_START { $<literal>$ = jv_string("text"); } QQString QQSTRING_END {
  $$ = $3;
  jv_free($<literal>2);
} |
FORMAT QQSTRING_START { $<literal>$ = $1; } QQString QQSTRING_END {
  $$ = $4;
  jv_free($<literal>3);
}


QQString:
%empty {
  $$ = ast_mk_const(jv_string(""));
} |
QQString QQSTRING_TEXT {
  $$ = gen_binop($1, ast_mk_const($2), '+');
} |
QQString QQSTRING_INTERP_START Exp QQSTRING_INTERP_END {
  $$ = gen_binop($1, gen_format($3, jv_copy($<literal>0)), '+');
}


ElseBody:
"elif" Exp "then" Exp ElseBody {
  $$ = ast_todo(gen_cond(ast_block($2), ast_block($4), ast_block($5)));
} |
"else" Exp "end" {
  $$ = $2;
}

ExpD:
ExpD '|' ExpD {
  $$ = ast_todo(block_join(ast_block($1), ast_block($3)));
} |
'-' ExpD {
  $$ = ast_todo(BLOCK(ast_block($2), gen_call("_negate", gen_noop())));
} |
Term {
  $$ = $1;
}


Term:
'.' {
  $$ = ast_mk_this();
} |
REC {
  $$ = ast_todo(gen_call("recurse", gen_noop()));
} |
BREAK '$' IDENT {
  jv v = jv_string_fmt("*label-%s", jv_string_value($3));     // impossible symbol
  $$ = ast_todo(gen_location(@$, locations,
                    BLOCK(gen_op_unbound(LOADV, jv_string_value(v)),
                    gen_call("error", gen_noop()))));
  jv_free(v);
  jv_free($3);
} |
BREAK error {
  FAIL(@$, "break requires a label to break to");
  $$ = NULL;
} |
Term FIELD '?' {
  $$ = ast_mk_index_opt($1, ast_mk_const($2));
} |
FIELD '?' {
  $$ = ast_mk_index_opt(ast_mk_this(), ast_mk_const($1));
} |
Term '.' String '?' {
  $$ = ast_mk_index_opt($1, $3);
} |
'.' String '?' {
  $$ = ast_mk_index_opt(ast_mk_this(), $2);
} |
Term FIELD %prec NONOPT {
  $$ = ast_mk_index($1, ast_mk_const($2));
} |
FIELD %prec NONOPT {
  $$ = ast_mk_index(ast_mk_this(), ast_mk_const($1));
} |
Term '.' String %prec NONOPT {
  $$ = ast_mk_index($1, $3);
} |
'.' String %prec NONOPT {
  $$ = ast_mk_index(ast_mk_this(), $2);
} |
'.' error {
  FAIL(@$, "try .[\"field\"] instead of .field for unusually named fields");
  $$ = NULL;
} |
'.' IDENT error {
  jv_free($2);
  FAIL(@$, "try .[\"field\"] instead of .field for unusually named fields");
  $$ = NULL;
} |
/* FIXME: string literals */
Term '[' Exp ']' '?' {
  $$ = ast_mk_index_opt($1, $3);
} |
Term '[' Exp ']' %prec NONOPT {
  $$ = ast_mk_index($1, $3);
} |
Term '[' ']' '?' {
  $$ = ast_todo(block_join(ast_block($1), gen_op_simple(EACH_OPT)));
} |
Term '[' ']' %prec NONOPT {
  $$ = ast_todo(block_join(ast_block($1), gen_op_simple(EACH)));
} |
Term '[' Exp ':' Exp ']' '?' {
  $$ = ast_todo(gen_slice_index(ast_block($1), ast_block($3), ast_block($5), INDEX_OPT));
} |
Term '[' Exp ':' ']' '?' {
  $$ = ast_todo(gen_slice_index(ast_block($1), ast_block($3), gen_const(jv_null()), INDEX_OPT));
} |
Term '[' ':' Exp ']' '?' {
  $$ = ast_todo(gen_slice_index(ast_block($1), gen_const(jv_null()), ast_block($4), INDEX_OPT));
} |
Term '[' Exp ':' Exp ']' %prec NONOPT {
  $$ = ast_todo(gen_slice_index(ast_block($1), ast_block($3), ast_block($5), INDEX));
} |
Term '[' Exp ':' ']' %prec NONOPT {
  $$ = ast_todo(gen_slice_index(ast_block($1), ast_block($3), gen_const(jv_null()), INDEX));
} |
Term '[' ':' Exp ']' %prec NONOPT {
  $$ = ast_todo(gen_slice_index(ast_block($1), gen_const(jv_null()), ast_block($4), INDEX));
} |
LITERAL {
  $$ = ast_mk_const($1);
} |
String {
  $$ = $1;
} |
FORMAT {
  $$ = gen_format(ast_mk_this(), $1);
} |
'(' Exp ')' {
  $$ = $2;
} |
'[' Exp ']' {
  $$ = ast_todo(gen_collect(ast_block($2)));
} |
'[' ']' {
  $$ = ast_mk_const(jv_array());
} |
'{' MkDict '}' {
  block x = ast_block($2);
  block o = gen_const_object(x);
  if (o.first != NULL)
    $$ = ast_todo(o);
  else
    $$ = ast_todo(BLOCK(gen_subexp(gen_const(jv_object())), x, gen_op_simple(POP)));
} |
'$' LOC {
  $$ = ast_mk_const(JV_OBJECT(jv_string("file"), jv_copy(locations->fname),
                           jv_string("line"), jv_number(locfile_get_line(locations, @$.start) + 1)));
} |
'$' IDENT {
  $$ = ast_todo(gen_location(@$, locations, gen_op_unbound(LOADV, jv_string_value($2))));
  jv_free($2);
} |
IDENT {
  const char *s = jv_string_value($1);
  if (strcmp(s, "false") == 0)
    $$ = ast_mk_const(jv_false());
  else if (strcmp(s, "true") == 0)
    $$ = ast_mk_const(jv_true());
  else if (strcmp(s, "null") == 0)
    $$ = ast_mk_const(jv_null());
  else
    $$ = ast_todo(gen_location(@$, locations, gen_call(s, gen_noop())));
  jv_free($1);
} |
IDENT '(' Args ')' {
  $$ = ast_todo(gen_call(jv_string_value($1), ast_block($3)));
  $$ = ast_todo(gen_location(@1, locations, ast_block($$)));
  jv_free($1);
} |
'(' error ')' { $$ = NULL; } |
'[' error ']' { $$ = NULL; } |
Term '[' error ']' { $$ = $1; } |
'{' error '}' { $$ = NULL; }

Args:
Arg {
  $$ = $1;
} |
Args ';' Arg {
  $$ = ast_todo(BLOCK(ast_block($1), ast_block($3)));
}

Arg:
Exp {
  $$ = ast_todo(gen_lambda(ast_block($1)));
}

Pattern:
'$' IDENT {
  $$ = ast_todo(gen_op_unbound(STOREV, jv_string_value($2)));
  jv_free($2);
} |
'[' ArrayPats ']' {
  $$ = ast_todo(BLOCK(ast_block($2), gen_op_simple(POP)));
} |
'{' ObjPats '}' {
  $$ = ast_todo(BLOCK(ast_block($2), gen_op_simple(POP)));
}

ArrayPats:
Pattern {
  $$ = ast_todo(gen_array_matcher(gen_noop(), ast_block($1)));
} |
ArrayPats ',' Pattern {
  $$ = ast_todo(gen_array_matcher(ast_block($1), ast_block($3)));
}

ObjPats:
ObjPat {
  $$ = $1;
} |
ObjPats ',' ObjPat {
  $$ = ast_todo(BLOCK(ast_block($1), ast_block($3)));
}

ObjPat:
'$' IDENT {
  $$ = ast_todo(gen_object_matcher(gen_const($2), gen_op_unbound(STOREV, jv_string_value($2))));
} |
IDENT ':' Pattern {
  $$ = ast_todo(gen_object_matcher(gen_const($1), ast_block($3)));
} |
Keyword ':' Pattern {
  $$ = ast_todo(gen_object_matcher(gen_const($1), ast_block($3)));
} |
String ':' Pattern {
  $$ = ast_todo(gen_object_matcher(ast_block($1), ast_block($3)));
} |
'(' Exp ')' ':' Pattern {
  $$ = ast_todo(gen_object_matcher(ast_block($2), ast_block($5)));
}

Keyword:
"as" {
  $$ = jv_string("as");
} |
"def" {
  $$ = jv_string("def");
} |
"module" {
  $$ = jv_string("module");
} |
"import" {
  $$ = jv_string("import");
} |
"include" {
  $$ = jv_string("include");
} |
"if" {
  $$ = jv_string("if");
} |
"then" {
  $$ = jv_string("then");
} |
"else" {
  $$ = jv_string("else");
} |
"elif" {
  $$ = jv_string("elif");
} |
"reduce" {
  $$ = jv_string("reduce");
} |
"foreach" {
  $$ = jv_string("foreach");
} |
"end" {
  $$ = jv_string("end");
} |
"and" {
  $$ = jv_string("and");
} |
"or" {
  $$ = jv_string("or");
} |
"try" {
  $$ = jv_string("try");
} |
"catch" {
  $$ = jv_string("catch");
} |
"label" {
  $$ = jv_string("label");
} |
"break" {
  $$ = jv_string("break");
} |
"__loc__" {
  $$ = jv_string("__loc__");
}

MkDict:
%empty {
  $$ = NULL;
} |
 MkDictPair { $$ = $1; }
| MkDictPair ',' MkDict { $$=ast_todo(block_join(ast_block($1), ast_block($3))); }
| error ',' MkDict { $$ = $3; }

MkDictPair:
IDENT ':' ExpD {
  $$ = gen_dictpair(ast_mk_const($1), $3);
 }
| Keyword ':' ExpD {
  $$ = gen_dictpair(ast_mk_const($1), $3);
  }
| String ':' ExpD {
  $$ = gen_dictpair($1, $3);
  }
| String {
  $$ = gen_dictpair($1, ast_todo(BLOCK(gen_op_simple(POP), gen_op_simple(DUP2),
                              gen_op_simple(DUP2), gen_op_simple(INDEX))));
  }
| '$' IDENT {
  $$ = gen_dictpair(ast_mk_const($2),
                    ast_todo(gen_location(@$, locations, gen_op_unbound(LOADV, jv_string_value($2)))));
  }
| IDENT {
  $$ = gen_dictpair(ast_mk_const(jv_copy($1)),
                    ast_mk_index(ast_todo(gen_noop()), ast_mk_const($1)));
  }
| '(' Exp ')' ':' ExpD {
  $$ = gen_dictpair($2, $5);
  }
| '(' error ')' ':' ExpD { $$ = $5; }
%%

int jq_parse(struct locfile* locations, ast_node** answer) {
  struct lexer_param scanner;
  YY_BUFFER_STATE buf;
  jq_yylex_init_extra(0, &scanner.lexer);
  buf = jq_yy_scan_bytes(locations->data, locations->length, scanner.lexer);
  int errors = 0;
  *answer = NULL;
  yyparse(answer, &errors, locations, &scanner);
  jq_yy_delete_buffer(buf, scanner.lexer);
  jq_yylex_destroy(scanner.lexer);
  if (errors > 0 && *answer) {
    block_free(ast_block(*answer));
    *answer = NULL;
  }
  return errors;
}

int jq_parse_library(struct locfile* locations, ast_node** answer) {
  int errs = jq_parse(locations, answer);
  if (errs) return errs;
  block blk = ast_compile(*answer, 0);
  if (block_has_main(blk)) {
    locfile_locate(locations, UNKNOWN_LOCATION, "jq: error: library should only have function definitions, not a main expression");
    return 1;
  }
  assert(block_has_only_binders_and_imports(blk, OP_IS_CALL_PSEUDO));
  return 0;
}
