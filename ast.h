#ifndef AST_H
#define AST_H

#include "compile.h"

typedef enum {
  AST_PLUS,
  AST_MINUS,
  AST_TIMES,
  AST_DIV,
  AST_MOD,
  AST_EQ,
  AST_NEQ,
  AST_LT,
  AST_GT,
  AST_LEQ,
  AST_GEQ,
} ast_binop;

typedef struct ast_node ast_node;

block ast_compile(const ast_node *node, int codegen);
const char *ast_codegen(const ast_node *node);
void ast_free(ast_node *node);

ast_node *ast_todo(block blk);
block ast_block(ast_node *node);

ast_node *ast_mk_this(void);
ast_node *ast_mk_const(jv val);
ast_node *ast_mk_index(ast_node *obj, ast_node *key);
ast_node *ast_mk_index_opt(ast_node *obj, ast_node *key);
ast_node *ast_mk_binop(ast_node *lhs, ast_node *rhs, ast_binop op);
ast_node *ast_mk_compose(ast_node *lhs, ast_node *rhs);
ast_node *ast_mk_both(ast_node *first, ast_node *second);

// TODO dtolnay rewrite linker to operate on ast instead of block
ast_node * ast_mk_top(ast_node *module, ast_node *imports, ast_node *prog);
ast_node *ast_mk_link_libs(block libs, ast_node *prog);

#endif
