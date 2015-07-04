#ifndef RUNTIME_H
#define RUNTIME_H

#include "jv.h"

jv jvr_type_error2(jv bad1, jv bad2, const char *msg);
jv jvr_plus(jv a, jv b);
jv jvr_minus(jv a, jv b);

#endif
