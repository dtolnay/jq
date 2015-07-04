#include "ast.hpp"

void ast_free(ast_node *node) {
  jv_delete(node);
}

block ast_compile(const ast_node *node, int codegen) {
  return node ? node->compile(codegen) : gen_noop();
}

block ast_block(ast_node *node) {
  block blk = ast_compile(node, false);
  ast_free(node);
  return blk;
}

ast_node::~ast_node() {
}

ast_node *ast_todo(block blk) {
  return jv_new<ast_todo_node>(blk);
}

ast_todo_node::ast_todo_node(block blk) : blk(blk) {
}

block ast_todo_node::compile(bool) const {
  return blk;
}

ast_node *ast_mk_const(jv val) {
  return jv_new<ast_const_node>(val);
}

ast_const_node::ast_const_node(jv val) : val(val) {
  assert(jv_is_valid(val));
}

block ast_const_node::compile(bool) const {
  return gen_const(val);
}

ast_node *ast_mk_this() {
  return jv_new<ast_this_node>();
}

block ast_this_node::compile(bool) const {
  return gen_noop();
}

ast_node *ast_mk_index(ast_node *obj, ast_node *key) {
  return jv_new<ast_index_node>(obj, key, false);
}

ast_index_node::ast_index_node(ast_node *obj, ast_node *key, bool opt)
    : obj(obj), key(key), opt(opt) {
}

ast_node *ast_mk_index_opt(ast_node *obj, ast_node *key) {
  return jv_new<ast_index_node>(obj, key, true);
}

block ast_index_node::compile(bool codegen) const {
  if (codegen) {
    const char *name = ast_codegen(this);
    if (name) {
      return gen_call_native(name);
    }
  }
  opcode index_op = opt ? INDEX_OPT : INDEX;
  return BLOCK(gen_subexp(key->compile(codegen)),
               obj->compile(codegen),
               gen_op_simple(index_op));
}

ast_node *ast_mk_binop(ast_node *lhs, ast_node *rhs, ast_binop op) {
  return jv_new<ast_binop_node>(lhs, rhs, op);
}

ast_binop_node::ast_binop_node(ast_node *lhs, ast_node *rhs, ast_binop op)
    : lhs(lhs), rhs(rhs), op(op) {
}

static block constant_fold(block a, block b, int op) {
  if (!block_is_single(a) || !block_is_const(a) || !block_is_single(b) ||
      !block_is_const(b))
    return gen_noop();
  if (block_const_kind(a) != block_const_kind(b))
    return gen_noop();

  jv res = jv_invalid();

  if (block_const_kind(a) == JV_KIND_NUMBER) {
    double na = jv_number_value(block_const(a));
    double nb = jv_number_value(block_const(b));
    switch (op) {
      case AST_PLUS:
        res = jv_number(na + nb);
        break;
      case AST_MINUS:
        res = jv_number(na - nb);
        break;
      case AST_TIMES:
        res = jv_number(na * nb);
        break;
      case AST_DIV:
        res = jv_number(na / nb);
        break;
      case AST_EQ:
        res = (na == nb ? jv_true() : jv_false());
        break;
      case AST_NEQ:
        res = (na != nb ? jv_true() : jv_false());
        break;
      case AST_LT:
        res = (na < nb ? jv_true() : jv_false());
        break;
      case AST_GT:
        res = (na > nb ? jv_true() : jv_false());
        break;
      case AST_LEQ:
        res = (na <= nb ? jv_true() : jv_false());
        break;
      case AST_GEQ:
        res = (na >= nb ? jv_true() : jv_false());
        break;
      default:
        break;
    }
  } else if (op == '+' && block_const_kind(a) == JV_KIND_STRING) {
    res = jv_string_concat(block_const(a), block_const(b));
  } else {
    return gen_noop();
  }

  if (jv_get_kind(res) == JV_KIND_INVALID)
    return gen_noop();

  block_free(a);
  block_free(b);
  return gen_const(res);
}

static block gen_binop(block a, block b, int op) {
  block folded = constant_fold(a, b, op);
  if (!block_is_noop(folded))
    return folded;

  const char *funcname = 0;
  switch (op) {
    case AST_PLUS:
      funcname = "_plus";
      break;
    case AST_MINUS:
      funcname = "_minus";
      break;
    case AST_TIMES:
      funcname = "_multiply";
      break;
    case AST_DIV:
      funcname = "_divide";
      break;
    case AST_MOD:
      funcname = "_mod";
      break;
    case AST_EQ:
      funcname = "_equal";
      break;
    case AST_NEQ:
      funcname = "_notequal";
      break;
    case AST_LT:
      funcname = "_less";
      break;
    case AST_GT:
      funcname = "_greater";
      break;
    case AST_LEQ:
      funcname = "_lesseq";
      break;
    case AST_GEQ:
      funcname = "_greatereq";
      break;
  }
  assert(funcname);

  return gen_call(funcname, BLOCK(gen_lambda(a), gen_lambda(b)));
}

block ast_binop_node::compile(bool codegen) const {
  if (codegen) {
    const char *name = ast_codegen(this);
    if (name) {
      return gen_call_native(name);
    }
  }
  return gen_binop(ast_compile(lhs, codegen), ast_compile(rhs, codegen), op);
}

ast_node *ast_mk_compose(ast_node *lhs, ast_node *rhs) {
  return jv_new<ast_compose_node>(lhs, rhs);
}

ast_compose_node::ast_compose_node(ast_node *lhs, ast_node *rhs)
    : lhs(lhs), rhs(rhs) {
}

block ast_compose_node::compile(bool codegen) const {
  if (codegen) {
    const char *name = ast_codegen(this);
    if (name) {
      return gen_call_native(name);
    }
  }
  return BLOCK(ast_compile(lhs, codegen), ast_compile(rhs, codegen));
}

ast_node *ast_mk_both(ast_node *first, ast_node *second) {
  return jv_new<ast_both_node>(first, second);
}

ast_both_node::ast_both_node(ast_node *first, ast_node *second)
    : first(first), second(second) {
}

block ast_both_node::compile(bool codegen) const {
  return gen_both(ast_compile(first, codegen), ast_compile(second, codegen));
}

ast_node *ast_mk_top(ast_node *module, ast_node *imports, ast_node *prog) {
  return jv_new<ast_top_node>(module, imports, prog);
}

ast_top_node::ast_top_node(ast_node *module, ast_node *imports, ast_node *prog)
    : module(module), imports(imports), prog(prog) {
}

block ast_top_node::compile(bool codegen) const {
  return BLOCK(ast_compile(module, codegen),
               ast_compile(imports, codegen),
               gen_op_simple(TOP),
               prog->compile(codegen));
}

ast_node *ast_mk_link_libs(block libs, ast_node *prog) {
  return jv_new<ast_link_libs_node>(libs, prog);
}

ast_link_libs_node::ast_link_libs_node(block libs, ast_node *prog)
    : libs(libs), prog(prog) {
}

block ast_link_libs_node::compile(bool codegen) const {
  return block_drop_unreferenced(BLOCK(libs, prog->compile(codegen)));
}
