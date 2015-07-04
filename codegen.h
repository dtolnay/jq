#ifndef CODEGEN_H
#define CODEGEN_H

#include "jv.h"

void codegen_init(void);
void codegen_dump(void);
void codegen_finalize(void);
jv (*codegen_get_address(const char *name))(jv);
void codegen_teardown(void);

#endif
