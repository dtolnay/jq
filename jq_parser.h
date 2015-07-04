#ifndef JQ_PARSER_H
#define JQ_PARSER_H
#include "ast.h"
#include "locfile.h"
#include "compile.h"

int jq_parse(struct locfile* source, ast_node** answer);
int jq_parse_library(struct locfile* locations, ast_node** answer);

#endif
