/*
 * Author: yf36
 * License: BSD
 */

#ifndef LICENCE_CXX_MACROS_H_
#define LICENCE_CXX_MACROS_H_

// A macro to forbid the compiler to generate copy constrcutor, move
// constructor, and assign function which usually are error-prone.
//
// We will always encounter compile-time errors if we use them unknowingly.
#define DISABLE_COPY_MOVE_AND_ASSIGN(name) \
  name(const name &) = delete;             \
  name(name &&) = delete;                  \
  name &operator=(const name &) = delete;  \
  name &operator=(name &&) = delete

#endif  // LICENCE_CXX_MACROS_H_
