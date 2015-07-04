#include <cctype>
#include <cstdio>
#include <map>
#include <string>
#include <vector>

#include "llvm/Analysis/Passes.h"
#include "llvm/ExecutionEngine/ExecutionEngine.h"
#include "llvm/ExecutionEngine/MCJIT.h"
#include "llvm/ExecutionEngine/SectionMemoryManager.h"
#include "llvm/IR/AssemblyAnnotationWriter.h"
#include "llvm/IR/DataLayout.h"
#include "llvm/IR/DerivedTypes.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/LLVMContext.h"
#include "llvm/IR/MDBuilder.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Verifier.h"
#include "llvm/PassManager.h"
#include "llvm/Support/FormattedStream.h"
#include "llvm/Support/ManagedStatic.h"
#include "llvm/Support/TargetSelect.h"
#include "llvm/Transforms/Scalar.h"

extern "C" {
#include "codegen.h"
}

#include "ast.hpp"

using namespace llvm;

const size_t jv_bits = sizeof(jv) * CHAR_BIT;
Type *const raw_jv_type = IntegerType::get(getGlobalContext(), jv_bits);
Type *const jv_type = StructType::create(raw_jv_type, "jv");
Type *const maybe_jv_type = StructType::create(raw_jv_type, "maybe_jv");
Type *const bool_type =
    StructType::create(IntegerType::get(getGlobalContext(), 1), "bool");

static ExecutionEngine *TheExecutionEngine;
static Module *TheModule;
static IRBuilder<> Builder{getGlobalContext()};
static FunctionPassManager *TheFPM;

/*
 * An optimization pass that eliminates pairs of jv_copy and jv_free calls by
 * combining a jv_free call with the most recent preceding jv_copy call of the
 * same value within the same basic block. This is valid as long as all
 * functions called from generated code free all of their jv arguments.
 */
struct CopyElimination : public BasicBlockPass {
  static char ID;
  CopyElimination();
  bool runOnBasicBlock(BasicBlock &bb) override;
};
char CopyElimination::ID = 0;
CopyElimination::CopyElimination() : BasicBlockPass(ID) {
}
bool CopyElimination::runOnBasicBlock(BasicBlock &bb) {
  bool changed = false;
  Function *jv_free_f = TheModule->getFunction("jv_free");
  Function *jv_copy_f = TheModule->getFunction("jv_copy");
  BasicBlock::iterator bbbegin = bb.begin(), bbend = bb.end();
  for (BasicBlock::iterator bbit = bbbegin; bbit != bbend;) {
    BasicBlock::iterator orig = bbit;
    ++bbit;
    llvm::CallInst *maybeFreeInst = llvm::dyn_cast<llvm::CallInst>(orig);
    if (!maybeFreeInst || maybeFreeInst->getCalledFunction() != jv_free_f) {
      continue; // not a call to jv_free
    }
    for (BasicBlock::iterator bbfind = orig; bbfind != bbbegin;) {
      --bbfind;
      llvm::CallInst *maybeCopyInst = llvm::dyn_cast<llvm::CallInst>(bbfind);
      if (!maybeCopyInst || maybeCopyInst->getCalledFunction() != jv_copy_f) {
        continue; // not a call to jv_copy
      }
      if (maybeCopyInst->getArgOperand(0) != maybeFreeInst->getArgOperand(0)) {
        continue; // not copying the same value
      }
      bbfind->eraseFromParent();
      orig->eraseFromParent();
      changed = true;
      break;
    }
  }
  return changed;
}

void codegen_init() {
  InitializeNativeTarget();
  InitializeNativeTargetAsmPrinter();
  LLVMContext &Context = getGlobalContext();

  // Make the module, which holds all the code.
  std::unique_ptr<Module> Owner = make_unique<Module>("jq", Context);
  TheModule = Owner.get();

  // Create the JIT.  This takes ownership of the module.
  std::string ErrStr;
  TheExecutionEngine =
      EngineBuilder{std::move(Owner)}
          .setErrorStr(&ErrStr)
          .setMCJITMemoryManager(make_unique<SectionMemoryManager>())
          .create();
  if (!TheExecutionEngine) {
    fprintf(stderr, "Could not create ExecutionEngine: %s\n", ErrStr.c_str());
    exit(1);
  }

  TheFPM = new FunctionPassManager{TheModule};

  // Set up the optimizer pipeline.  Start with registering info about how the
  // target lays out data structures.
  TheModule->setDataLayout(TheExecutionEngine->getDataLayout());
  TheFPM->add(new DataLayoutPass{});
  // Provide basic AliasAnalysis support for GVN.
  TheFPM->add(createBasicAliasAnalysisPass());
  // Promote allocas to registers.
  TheFPM->add(createPromoteMemoryToRegisterPass());
  // Do simple "peephole" optimizations and bit-twiddling optimizations.
  TheFPM->add(createInstructionCombiningPass());
  // Reassociate expressions.
  TheFPM->add(createReassociatePass());
  // Eliminate Common SubExpressions.
  TheFPM->add(createGVNPass());
  // Simplify the control flow graph (deleting unreachable blocks, etc).
  TheFPM->add(createCFGSimplificationPass());
  // TODO dtolnay where to put this pass
  TheFPM->add(new CopyElimination{});

  TheFPM->doInitialization();

  atexit(codegen_teardown);
}

class JVAnnotator : public AssemblyAnnotationWriter {
  virtual void printInfoComment(const Value &,
                                formatted_raw_ostream &) override;
};

static void dump_value(const Value *val, formatted_raw_ostream &stream) {
  const ConstantInt *intval = dyn_cast<const ConstantInt>(val);
  if (intval && intval->getType() == raw_jv_type) {
    const uint64_t *data = intval->getValue().getRawData();
    jv j = *reinterpret_cast<const jv *>(data);
    assert(jv_is_valid(j));
    char buf[15];
    stream.PadToColumn(50);
    stream << "; " << jv_dump_string_trunc(jv_copy(j), buf, sizeof(buf));
  }
}

void JVAnnotator::printInfoComment(const Value &value,
                                   formatted_raw_ostream &stream) {
  const BitCastInst *cast = dyn_cast<BitCastInst>(&value);
  if (cast) {
    dump_value(cast->getOperand(0), stream);
    return;
  }
  const CallInst *call = dyn_cast<CallInst>(&value);
  if (call) {
    for (auto &arg : call->arg_operands()) {
      dump_value(arg.get(), stream);
    }
  }
}

void codegen_dump() {
  raw_fd_ostream stream{fileno(stdout), false};
  JVAnnotator annotator;
  TheModule->print(stream, &annotator);
}

void codegen_finalize() {
  Function *free_constants = TheModule->getFunction("jq_free_constants");
  if (free_constants) {
    Builder.SetInsertPoint(&free_constants->back());
    Builder.CreateRetVoid();
    verifyFunction(*free_constants);
    TheFPM->run(*free_constants);
  }
  TheExecutionEngine->finalizeObject();
}

jv (*codegen_get_address(const char *name))(jv) {
  auto addr = TheExecutionEngine->getFunctionAddress(name);
  return reinterpret_cast<jv (*)(jv)>(addr);
}

void codegen_teardown() {
  auto addr = TheExecutionEngine->getFunctionAddress("jq_free_constants");
  if (addr) {
    reinterpret_cast<void (*)()>(addr)();
  }
  delete TheExecutionEngine;
  llvm_shutdown();
}

static Value *constant_jv(jv j) {
  unsigned num64s = (sizeof(jv) + sizeof(uint64_t) - 1) / sizeof(uint64_t);
  ArrayRef<uint64_t> data{reinterpret_cast<const uint64_t *>(&j), num64s};
  return ConstantInt::get(jv_type, APInt{jv_bits, data});
}

static Function *ExternalFunction(const char *name, FunctionType *type) {
  Function *existing = TheModule->getFunction(name);
  if (existing) {
    return existing;
  }
  return Function::Create(type, Function::ExternalLinkage, name, TheModule);
}

static void CreateCopy(Value *v) {
  Function *copy_f = ExternalFunction(
      "jv_copy",
      FunctionType::get(jv_type, std::vector<Type *>{jv_type}, false));
  Builder.CreateCall(copy_f, std::vector<Value *>{v});
}

static void CreateFree(Value *v) {
  Type *voidTy = Type::getVoidTy(getGlobalContext());
  Function *free_f = ExternalFunction(
      "jv_free",
      FunctionType::get(voidTy, std::vector<Type *>{jv_type}, false));
  Builder.CreateCall(free_f, std::vector<Value *>{v});
}

static void free_later(jv v) {
  switch (jv_get_kind(v)) {
    case JV_KIND_ARRAY:
    case JV_KIND_STRING:
    case JV_KIND_OBJECT:
      break;
    case JV_KIND_INVALID:
      assert(0);
    default:
      return;
  }
  auto insertPoint = Builder.saveIP();
  Function *free_constants = TheModule->getFunction("jq_free_constants");
  if (!free_constants) {
    Type *voidTy = Type::getVoidTy(getGlobalContext());
    FunctionType *FT = FunctionType::get(voidTy, false);
    free_constants = Function::Create(
        FT, Function::ExternalLinkage, "jq_free_constants", TheModule);
    BasicBlock::Create(getGlobalContext(), "", free_constants);
  }
  Builder.SetInsertPoint(&free_constants->back());
  CreateFree(constant_jv(v));
  Builder.restoreIP(insertPoint);
}

static Value *dot;

const char *ast_codegen(const ast_node *node) {
  static unsigned counter = 0;

  FunctionType *FT = FunctionType::get(maybe_jv_type, jv_type, false);
  Function *TheFunction =
      Function::Create(FT, Function::ExternalLinkage, "", TheModule);

  // Create a new basic block to start insertion into.
  BasicBlock *bb = BasicBlock::Create(getGlobalContext(), "", TheFunction);
  Builder.SetInsertPoint(bb);

  dot = TheFunction->arg_begin();
  dot->setName(".");

  Value *RetVal = node->codegen();
  if (!RetVal) {
    // could not generate function
    TheFunction->eraseFromParent();
    return nullptr;
  }

  CreateFree(dot);
  Builder.CreateRet(RetVal);

  // Validate the generated code, checking for consistency.
  verifyFunction(*TheFunction);

  // Optimize the function.
  TheFPM->run(*TheFunction);

  TheFunction->setName(Twine{"jq_codegen_"} + Twine{counter++});
  return TheFunction->getName().data();
}

bool ast_todo_node::can_codegen() const {
  return false;
}

Value *ast_todo_node::codegen() const {
  return nullptr;
}

bool ast_const_node::can_codegen() const {
  return true;
}

Value *ast_const_node::codegen() const {
  free_later(val);
  Value *v = constant_jv(val);
  CreateCopy(v);
  return v;
}

bool ast_this_node::can_codegen() const {
  return true;
}

Value *ast_this_node::codegen() const {
  CreateCopy(dot);
  return dot;
}

struct ValidCheck {
  PHINode *merge;
};

ValidCheck check_valid(Value *input, Value *cleanup = nullptr) {
  if (input->getType() != maybe_jv_type) {
    return {nullptr};
  }

  Function *valid_f = ExternalFunction(
      "jvr_is_valid", FunctionType::get(bool_type, maybe_jv_type, false));
  valid_f->addAttribute(0, Attribute::ReadNone);
  Value *valid = Builder.CreateCall(valid_f, input);

  BasicBlock *curr_bb = Builder.GetInsertBlock();
  BasicBlock *next_bb = ++Function::iterator(curr_bb);
  BasicBlock *valid_bb = BasicBlock::Create(
      getGlobalContext(), "valid", curr_bb->getParent(), next_bb);
  BasicBlock *merge_bb = BasicBlock::Create(
      getGlobalContext(), "merge", curr_bb->getParent(), next_bb);

  BasicBlock *cleanup_bb = merge_bb;
  if (cleanup) {
    cleanup_bb = BasicBlock::Create(
        getGlobalContext(), "cleanup", curr_bb->getParent(), merge_bb);
  }

  MDNode *weights = MDBuilder(getGlobalContext()).createBranchWeights(1, 0);
  Builder.CreateCondBr(valid, valid_bb, cleanup_bb, weights);

  Builder.SetInsertPoint(merge_bb);
  PHINode *phi = Builder.CreatePHI(maybe_jv_type, 2);
  if (cleanup) {
    phi->addIncoming(input, cleanup_bb);
    Builder.SetInsertPoint(cleanup_bb);
    CreateFree(cleanup);
    Builder.CreateBr(merge_bb);
  } else {
    phi->addIncoming(input, curr_bb);
  }

  Builder.SetInsertPoint(valid_bb);
  return {phi};
}

Value *finish_check(ValidCheck state, Value *output) {
  if (!state.merge) {
    return output;
  }
  if (output->getType() != maybe_jv_type) {
    output = Builder.CreateBitCast(output, maybe_jv_type);
  }
  state.merge->addIncoming(output, Builder.GetInsertBlock());
  Builder.CreateBr(state.merge->getParent());
  Builder.SetInsertPoint(state.merge->getParent());
  return state.merge;
}

bool ast_index_node::can_codegen() const {
  return obj->can_codegen() && key->can_codegen();
}

Value *ast_index_node::codegen() const {
  if (!can_codegen()) {
    return nullptr;
  }

  Value *obj_v = obj->codegen();
  ValidCheck obj_check = check_valid(obj_v);

  Value *key_v = key->codegen();
  ValidCheck key_check = check_valid(key_v, obj_v);

  Function *jv_get_f = ExternalFunction(
      "jv_get",
      FunctionType::get(
          maybe_jv_type, std::vector<Type *>{jv_type, jv_type}, false));

  Value *v = Builder.CreateCall(jv_get_f, std::vector<Value *>{obj_v, key_v});

  v = finish_check(key_check, v);
  v = finish_check(obj_check, v);
  return v;
}

extern "C" bool jvr_is_valid(jv j) {
  return jv_is_valid(j);
}

bool ast_binop_node::can_codegen() const {
  return lhs->can_codegen() && rhs->can_codegen();
}

Value *ast_binop_node::codegen() const {
  if (!can_codegen()) {
    return nullptr;
  }

  Value *lhs_v = lhs->codegen();
  ValidCheck lhs_check = check_valid(lhs_v);

  Value *rhs_v = rhs->codegen();
  ValidCheck rhs_check = check_valid(rhs_v, lhs_v);

  const char *funcname = nullptr;
  switch (op) {
    case AST_PLUS:
      funcname = "jvr_plus";
      break;
    case AST_MINUS:
      funcname = "jvr_minus";
      break;
    default:
      break;
  }
  assert(funcname);

  Function *op_f = ExternalFunction(
      funcname,
      FunctionType::get(
          maybe_jv_type, std::vector<Type *>{jv_type, jv_type}, false));

  Value *v = Builder.CreateCall(op_f, std::vector<Value *>{lhs_v, rhs_v});

  v = finish_check(rhs_check, v);
  v = finish_check(lhs_check, v);
  return v;
}

bool ast_compose_node::can_codegen() const {
  return lhs->can_codegen() && rhs->can_codegen();
}

Value *ast_compose_node::codegen() const {
  if (!can_codegen()) {
    return nullptr;
  }

  Value *lhs_v = lhs->codegen();
  ValidCheck lhs_check = check_valid(lhs_v);

  Value *prev_dot = dot;
  dot = Builder.CreateBitCast(lhs_v, raw_jv_type);

  Value *rhs_v = rhs->codegen();

  dot = prev_dot;

  return finish_check(lhs_check, rhs_v);
}

bool ast_both_node::can_codegen() const {
  return false;
}

Value *ast_both_node::codegen() const {
  return nullptr;
}

bool ast_link_libs_node::can_codegen() const {
  return prog->can_codegen();
}

Value *ast_link_libs_node::codegen() const {
  return prog->codegen();
}

bool ast_top_node::can_codegen() const {
  return prog->can_codegen();
}

Value *ast_top_node::codegen() const {
  return prog->codegen();
}
