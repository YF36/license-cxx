/*
 * Author: yf36
 * License: BSD
 */

#include "auth_util.h"

int main(int argc, char *argv[]) {
  if (argc != 4) {
    fprintf(stderr, "Usage: a.out <private_key_file_path> <expire_time_point_str> <machine_id>\n");
    return 1;
  }
  printf("private_key_file_path: %s, expire_time_point_str: %s, machine_id: %s\n", argv[1], argv[2], argv[3]);

  license_cxx::AuthUtil auth_util; 
  auth_util.set_private_key_file_path(argv[1]);

  std::string time_point_str = argv[2];
  std::string machine_id = argv[3];
  if (!auth_util.generateLicense(time_point_str, machine_id, "license_cxx.lic")) {
    fprintf(stderr, "generate fail\n");
    return 1;
  }

  printf("generate finish\n");
  return 0;
}
