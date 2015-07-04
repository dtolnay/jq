#ifndef JV_NEW_HPP
#define JV_NEW_HPP

extern "C" {
#include "jv_alloc.h"
}

template <typename T, typename... Args>
T *jv_new(Args &&... args) {
  T *obj = static_cast<T *>(jv_mem_alloc(sizeof(T)));
  return new (obj) T{std::forward<Args>(args)...};
}

template <typename T>
void jv_delete(T *obj) {
  if (obj) {
    obj->~T();
    jv_mem_free(obj);
  }
}

template <typename T>
class jv_ptr {
 public:
  jv_ptr(T *ptr) : ptr(ptr, jv_delete<T>) {
  }
  operator T *() const {
    return ptr.get();
  }
  T *operator->() const {
    return ptr.operator->();
  }

 private:
  std::unique_ptr<T, void (*)(T *)> ptr;
};

#endif
