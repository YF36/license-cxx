/*
 * Author: yf36
 * License: BSD
 */

#ifndef LICENCE_CXX_RSA_UTIL_H_
#define LICENCE_CXX_RSA_UTIL_H_

#include <openssl/rsa.h>

#include <string>

#include "macros.h"

namespace license_cxx {

class RsaUtil {
 public:
  RsaUtil();
  ~RsaUtil();

  bool ReadPemPublicKeyFile(const std::string &file_path);
  bool ReadPemPublicKeyString(const std::string &s);
  bool ReadPemPrivateKeyFile(const std::string &file_path);

  bool sign(const std::string &s, std::string *base64_sign);
  bool verify(const std::string &s, const std::string &base64_sign);

  static bool sha256(const std::string &s, std::string *result);

 private:
  RSA* rsa_public_key_;
  RSA* rsa_private_key_;

  DISABLE_COPY_MOVE_AND_ASSIGN(RsaUtil);
};

}  // namespace license_cxx

#endif  // LICENCE_CXX_RSA_UTIL_H_
