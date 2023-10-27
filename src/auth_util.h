/*
 * Author: yf36
 * License: BSD
 */

#ifndef LICENCE_CXX_AUTH_UTIL_H_
#define LICENCE_CXX_AUTH_UTIL_H_

#include "macros.h"

#include <memory>
#include <string>

#include "rsa_util.h"

namespace license_cxx {

enum AuthValidateCode {
  LICENSE_OK = 0,

  LICENSE_FILE_NOT_FOUND = 1,
  LICENSE_FILE_FORMAT_NOT_RECOGNIZED = 2,
  LICENSE_MALFORMED = 3,
  LICENSE_CORRUPTED = 4,
  LICENSE_EXPIRED = 5,
  IDENTIFIERS_MISMATCH = 6,

  KEY_FILE_NOT_FOUND = 10,
};

class AuthUtil {
 public:
  AuthUtil();
  ~AuthUtil() = default;

  void set_private_key_file_path(const std::string &file_path) {
    private_key_file_path_ = file_path;
  }

  void set_public_key_file_path(const std::string &file_path) {
    public_key_file_path_ = file_path;
  }

  // time_point_str format: %Y-%m-%d %H:%M:%S
  bool generateLicense(const std::string &time_point_str,
                       const std::string &mache_id,
                       const std::string &out_file_path);

  AuthValidateCode validateLicense(const std::string &license_file_path);

 private:
  std::string private_key_file_path_;
  std::string public_key_file_path_;
  std::unique_ptr<RsaUtil> rsa_util_;

  DISABLE_COPY_MOVE_AND_ASSIGN(AuthUtil);
};

}  // namespace license_cxx

#endif  // LICENCE_CXX_AUTH_UTIL_H_
