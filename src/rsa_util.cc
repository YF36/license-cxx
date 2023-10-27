/*
 * Author: yf36
 * License: BSD
 */

#include "rsa_util.h"

#include <stdio.h>
#include <string.h>
#include <openssl/pem.h>
#include <openssl/err.h>

#include <stdexcept>
#include <string>

#include "base64.h"

using std::string;

namespace license_cxx {

namespace {

// Use as a stack variable.
class FpGuard {
 public:
  explicit FpGuard(FILE *fp) : fp_(fp) {
  }

  ~FpGuard() {
    if (fp_ != nullptr) {
      fclose(fp_);
    }
  }

 private:
  FILE *fp_;

  DISABLE_COPY_MOVE_AND_ASSIGN(FpGuard);
};

// Prevent misuse like: FpGuard(db);
#define FpGuard(x) error "Missing guard object name"

void print_openssl_errors() {
  char buff[128];
  unsigned long code = ERR_get_error();
  while(code) {
    ERR_error_string_n(code, buff, sizeof(buff));
    fprintf(stderr, "errcode: %lu, errmsg: %s\n", code, buff);
    code = ERR_get_error();
  }
}

}  // namespace

RsaUtil::RsaUtil() : rsa_public_key_(nullptr), rsa_private_key_(nullptr) {
}

RsaUtil::~RsaUtil() {
  if (rsa_public_key_) {
    RSA_free(rsa_public_key_);
  }
  if (rsa_private_key_) {
    RSA_free(rsa_private_key_);
  }
}

bool RsaUtil::ReadPemPublicKeyFile(const string &file_path) {
  if (file_path.empty()) {
    return false;
  }

  FILE *fp = fopen(file_path.c_str(), "rb");
  if (fp == NULL){
    fprintf(stderr, "Open file error. file: %s, error: %s\n", file_path.c_str(), strerror(errno));
    return false;
  }
  FpGuard fp_guard(fp);

  // Read PEM format key.
  if (PEM_read_RSA_PUBKEY(fp, &rsa_public_key_, NULL, NULL) == NULL) {
    print_openssl_errors();
    return false;
  }

  return true;
}

bool RsaUtil::ReadPemPublicKeyString(const string &s) {
  if (s.empty()) {
    return false;
  }

  FILE *fp = fmemopen((void *)s.c_str(), s.size(), "rb");
  if (fp == NULL){
    fprintf(stderr, "Open file buffer error. buffer: %s, error: %s\n", s.c_str(), strerror(errno));
    return false;
  }
  FpGuard fp_guard(fp);

  // Read PEM format key.
  if (PEM_read_RSA_PUBKEY(fp, &rsa_public_key_, NULL, NULL) == NULL) {
    print_openssl_errors();
    return false;
  }

  return true;
}

bool RsaUtil::ReadPemPrivateKeyFile(const string &file_path) {
  if (file_path.empty()) {
    return false;
  }

  FILE *fp = fopen(file_path.c_str(), "rb");
  if (fp == NULL){
    fprintf(stderr, "Open file error.file: %s, error: %s\n", file_path.c_str(), strerror(errno));
    return false;
  }
  FpGuard fp_guard(fp);

  // Read PEM format key.
  if (PEM_read_RSAPrivateKey(fp, &rsa_private_key_, NULL, NULL) == NULL) {
    print_openssl_errors();
    return false;
  }

  return true;
}

bool RsaUtil::sha256(const string &s, string *result) {
  if (s.empty() || result == nullptr) {
    return false;
  }

  result->clear();

  unsigned char hash_sign[SHA256_DIGEST_LENGTH];
  if (SHA256((const unsigned char *)s.c_str(), s.size(), hash_sign) == NULL) {
    print_openssl_errors();
    return false;
  }

  *result = base64_encode(hash_sign, SHA256_DIGEST_LENGTH);
  return true;
}

bool RsaUtil::sign(const string &s, string *sign) {
  if (s.empty() || sign == nullptr) {
    return false;
  }

  sign->clear();

  if (rsa_private_key_ == nullptr) {
    fprintf(stderr, "call ReadPemPrivateKeyFile before sign");
    return false;
  }

  unsigned char hash_sign[SHA256_DIGEST_LENGTH];
  if (SHA256((const unsigned char *)s.c_str(), s.size(), hash_sign) == NULL) {
    print_openssl_errors();
    return false;
  }

  unsigned char sign_buff[4096] = {0};
  unsigned int sign_len = 0;
  int ret = RSA_sign(NID_sha256, hash_sign, SHA256_DIGEST_LENGTH, sign_buff, &sign_len, rsa_private_key_);

  if (ret != 1) {
    print_openssl_errors();
    return false;
  }

  *sign = base64_encode(sign_buff, sign_len);
  return true;
}

bool RsaUtil::verify(const string &s, const string &base64_sign) {
  if (base64_sign.empty() || s.empty()) {
    return false;
  }

  if (rsa_public_key_ == nullptr) {
    fprintf(stderr, "call ReadPemPublicKeyFile before sign");
    return false;
  }

  unsigned char hash_sign[SHA256_DIGEST_LENGTH];
  if (SHA256((const unsigned char *)s.c_str(), s.size(), hash_sign) == NULL) {
    print_openssl_errors();
    return false;
  }

  string sign;
  try {
    sign = base64_decode(base64_sign);
  } catch (std::runtime_error &e) {
    fprintf(stderr, "invalid sign str\n");
    return false;
  }

  int ret = RSA_verify(NID_sha256, hash_sign, SHA256_DIGEST_LENGTH, (unsigned char *)sign.c_str(), sign.size(), rsa_public_key_); 

  if (ret != 1) {
    print_openssl_errors();
    return false;
  }

  return true;
}

}  // namespace license_cxx
