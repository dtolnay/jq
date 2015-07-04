#include "runtime.h"

jv jvr_type_error2(jv bad1, jv bad2, const char *msg) {
  char errbuf1[15], errbuf2[15];
  jv err = jv_invalid_with_msg(jv_string_fmt(
      "%s (%s) and %s (%s) %s",
      jv_kind_name(jv_get_kind(bad1)),
      jv_dump_string_trunc(jv_copy(bad1), errbuf1, sizeof(errbuf1)),
      jv_kind_name(jv_get_kind(bad2)),
      jv_dump_string_trunc(jv_copy(bad2), errbuf2, sizeof(errbuf2)),
      msg));
  jv_free(bad1);
  jv_free(bad2);
  return err;
}

jv jvr_plus(jv a, jv b) {
  if (jv_get_kind(a) == JV_KIND_NULL) {
    jv_free(a);
    return b;
  } else if (jv_get_kind(b) == JV_KIND_NULL) {
    jv_free(b);
    return a;
  } else if (jv_get_kind(a) == JV_KIND_NUMBER &&
             jv_get_kind(b) == JV_KIND_NUMBER) {
    return jv_number(jv_number_value(a) + jv_number_value(b));
  } else if (jv_get_kind(a) == JV_KIND_STRING &&
             jv_get_kind(b) == JV_KIND_STRING) {
    return jv_string_concat(a, b);
  } else if (jv_get_kind(a) == JV_KIND_ARRAY &&
             jv_get_kind(b) == JV_KIND_ARRAY) {
    return jv_array_concat(a, b);
  } else if (jv_get_kind(a) == JV_KIND_OBJECT &&
             jv_get_kind(b) == JV_KIND_OBJECT) {
    return jv_object_merge(a, b);
  } else {
    return jvr_type_error2(a, b, "cannot be added");
  }
}

jv jvr_minus(jv a, jv b) {
  if (jv_get_kind(a) == JV_KIND_NUMBER && jv_get_kind(b) == JV_KIND_NUMBER) {
    return jv_number(jv_number_value(a) - jv_number_value(b));
  } else if (jv_get_kind(a) == JV_KIND_ARRAY && jv_get_kind(b) == JV_KIND_ARRAY) {
    jv out = jv_array();
    jv_array_foreach(a, i, x) {
      int include = 1;
      jv_array_foreach(b, j, y) {
        if (jv_equal(jv_copy(x), y)) {
          include = 0;
          break;
        }
      }
      if (include)
        out = jv_array_append(out, jv_copy(x));
      jv_free(x);
    }
    jv_free(a);
    jv_free(b);
    return out;
  } else {
    return jvr_type_error2(a, b, "cannot be subtracted");
  }
}
