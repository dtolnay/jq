#ifndef AST_HPP
#define AST_HPP

#include "llvm/IR/DerivedTypes.h"

extern "C" {
#include "ast.h"
}

#include "jv_new.hpp"

struct ast_node {
  virtual ~ast_node();
  virtual block compile(bool codegen) const = 0;
  virtual bool can_codegen() const = 0;
  virtual llvm::Value *codegen() const = 0;
};

class ast_todo_node : public ast_node {
 public:
  ast_todo_node(block blk);
  block compile(bool codegen) const override;
  bool can_codegen() const override;
  llvm::Value *codegen() const override;

 private:
  block blk;
};

class ast_const_node : public ast_node {
 public:
  ast_const_node(jv val);
  block compile(bool codegen) const override;
  bool can_codegen() const override;
  llvm::Value *codegen() const override;

 private:
  jv val;
};

class ast_this_node : public ast_node {
 public:
  block compile(bool codegen) const override;
  bool can_codegen() const override;
  llvm::Value *codegen() const override;
};

class ast_index_node : public ast_node {
 public:
  ast_index_node(ast_node *obj, ast_node *key, bool opt);
  block compile(bool codegen) const override;
  bool can_codegen() const override;
  llvm::Value *codegen() const override;

 private:
  jv_ptr<ast_node> obj;
  jv_ptr<ast_node> key;
  bool opt;
};

class ast_binop_node : public ast_node {
 public:
  ast_binop_node(ast_node *lhs, ast_node *rhs, ast_binop op);
  block compile(bool codegen) const override;
  bool can_codegen() const override;
  llvm::Value *codegen() const override;

 private:
  jv_ptr<ast_node> lhs;
  jv_ptr<ast_node> rhs;
  ast_binop op;
};

class ast_compose_node : public ast_node {
 public:
  ast_compose_node(ast_node *lhs, ast_node *rhs);
  block compile(bool codegen) const override;
  bool can_codegen() const override;
  llvm::Value *codegen() const override;

 private:
  jv_ptr<ast_node> lhs;
  jv_ptr<ast_node> rhs;
};

class ast_both_node : public ast_node {
 public:
  ast_both_node(ast_node *first, ast_node *second);
  block compile(bool codegen) const override;
  bool can_codegen() const override;
  llvm::Value *codegen() const override;

 private:
  jv_ptr<ast_node> first;
  jv_ptr<ast_node> second;
};

class ast_top_node : public ast_node {
 public:
  ast_top_node(ast_node *module, ast_node *imports, ast_node *prog);
  block compile(bool codegen) const override;
  bool can_codegen() const override;
  llvm::Value *codegen() const override;

 private:
  jv_ptr<ast_node> module;
  jv_ptr<ast_node> imports;
  jv_ptr<ast_node> prog;
};

class ast_link_libs_node : public ast_node {
 public:
  ast_link_libs_node(block libs, ast_node *prog);
  block compile(bool codegen) const override;
  bool can_codegen() const override;
  llvm::Value *codegen() const override;

 private:
  block libs;
  jv_ptr<ast_node> prog;
};

#endif
