/*
 * Author: yf36
 * License: BSD
 */

#include "auth_util.h"

#include <ctime>
#include <chrono>
#include <iomanip>
#include <sstream>
#include <unordered_map>

#include <unistd.h>
#include <time.h>

#include "inicpp.h"
#include "machineid.h"

using std::string;

namespace license_cxx {

namespace {

bool stringToTimePoint(const std::string &s, std::chrono::system_clock::time_point *tp) {
  if (s.empty() || tp == nullptr) {
    return false;
  }
  std::tm time_date = {};
  std::istringstream ss(s);
  ss >> std::get_time(&time_date, "%Y-%m-%d %H:%M:%S");
  if (ss.fail()) {
    return false;
  }
  *tp = std::chrono::system_clock::from_time_t(mktime(&time_date));
  return true;
}

}  // namespace

AuthUtil::AuthUtil() {
  rsa_util_.reset(new RsaUtil);
}

bool AuthUtil::generateLicense(const string &time_point_str,
                               const string &mache_id,
                               const string &out_file_path) {
  if (time_point_str.empty() || mache_id.empty() || out_file_path.empty()) {
    return false;
  }

  if (private_key_file_path_.empty()) {
    fprintf(stderr, "Set private key file path first\n");
    return false;
  }

  std::chrono::system_clock::time_point tp;
  if (!stringToTimePoint(time_point_str, &tp)) {
    fprintf(stderr, "Invalid time point format. format: %%Y-%%m-%%d %%H:%%M:%%S\n");
    return false;
  }

  if (!rsa_util_->ReadPemPrivateKeyFile(private_key_file_path_)) {
    fprintf(stderr, "ReadPemPrivateKeyFile fail\n");
    return false;
  }

  string s = time_point_str + ":" + mache_id;
  string base64_sign;
  if (!rsa_util_->sign(s, &base64_sign)) {
    fprintf(stderr, "Rsa sign fail\n");
    return false;
  }

  ini::IniFile ini_file;
  ini_file["LICENSE"]["expire"] = time_point_str;
  ini_file["LICENSE"]["sig"] = base64_sign;
  ini_file.save(out_file_path);
  return true;
}

AuthValidateCode AuthUtil::validateLicense(const string &license_file_path) {
  if (license_file_path.empty()) {
    return LICENSE_FILE_NOT_FOUND;
  }

  if (access(license_file_path.c_str(), F_OK) == -1) {
    return LICENSE_FILE_NOT_FOUND;
  }

  ini::IniFile ini_file;
  ini_file.load(license_file_path);

  if (ini_file.size() != 1) {
    return LICENSE_FILE_FORMAT_NOT_RECOGNIZED;
  }

  const string &time_point_str = ini_file["LICENSE"]["expire"].as<std::string>();
  if (time_point_str.empty()) {
    return LICENSE_MALFORMED;
  }

  std::chrono::system_clock::time_point expire_tp;
  if (!stringToTimePoint(time_point_str, &expire_tp)) {
    return LICENSE_CORRUPTED;
  }

  std::chrono::system_clock::time_point now_tp = std::chrono::system_clock::now();
  if (now_tp > expire_tp) {
    return LICENSE_EXPIRED;
  }

  if (public_key_file_path_.empty()) {
    return KEY_FILE_NOT_FOUND;
  }

  if (!rsa_util_->ReadPemPublicKeyFile(public_key_file_path_)) {
    return KEY_FILE_NOT_FOUND;
  }

  const string &base64_sign = ini_file["LICENSE"]["sig"].as<std::string>();
  if (base64_sign.empty()) {
    return LICENSE_MALFORMED;
  }

  string s = time_point_str + ":" + machineId();
  if (!rsa_util_->verify(s, base64_sign)) {
    return IDENTIFIERS_MISMATCH;
  }

  return LICENSE_OK;
}

}  // namespace license_cxx
