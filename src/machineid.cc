/*
 * Author: yf36
 * License: BSD
 */

#include "machineid.h"

#include <sys/socket.h>
#include <sys/types.h>
#include <cpuid.h>
#include <errno.h>
#include <linux/if.h>
#include <netinet/in.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/utsname.h>
#include <unistd.h>

#include <fstream>
#include <sstream>
#include <string>

#include "rsa_util.h"

namespace license_cxx {

std::string machineName() {
  static struct utsname u;
  if (uname(&u) < 0) {
    return "unknown";
  }
  return std::string(u.nodename);
}

unsigned short hashMacAddress(unsigned char *mac) {
  unsigned short hash = 0;
  for (unsigned int i = 0; i < 6; i++) {
    hash += (mac[i] << ((i & 1) * 8));
  }
  return hash;
}

std::string macAdrress() {
  // IPPROTO_IP = 0, /* Dummy protocol for TCP.  */
  int sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
  if (sockfd < 0) {
    return "";
  }

  // enumerate all IP addresses of the system
  char buff[128 * sizeof(struct ifreq)];
  memset(buff, 0, sizeof(buff));

  struct ifconf conf;
  conf.ifc_buf = buff;
  conf.ifc_len = sizeof(buff);

  if (ioctl(sockfd, SIOCGIFCONF, &conf) == -1) {
    fprintf(stderr, "ioctl failed: %s\n", strerror(errno));
    return "";
  }

  if (conf.ifc_len == sizeof(buff)) {
    fprintf(stderr, "ioctl buffer overflow");
    return "";
  }

  // get MAC address
  bool found = false;
  struct ifreq *ifr = nullptr;
  for (ifr = conf.ifc_req; (char *)ifr < (char *)conf.ifc_req + conf.ifc_len; ifr++) {
    if (ifr->ifr_addr.sa_data == (ifr + 1)->ifr_addr.sa_data) {
      // duplicate, skip it
      continue;
    }

    if (ioctl(sockfd, SIOCGIFFLAGS, ifr) == -1) {
      // failed to get flags, skip it
      continue;
    }

    if (ifr->ifr_flags & IFF_LOOPBACK) {
      // don't count loopback
      continue;
    }

    if (ioctl(sockfd, SIOCGIFHWADDR, ifr) == 0) {
      found = true;
      break;
    }
  }

  close(sockfd);

  if (found) {
    char mac_address[32];
    sprintf(
        mac_address, "%02x:%02x:%02x:%02x:%02x:%02x", (unsigned char)ifr->ifr_hwaddr.sa_data[0],
        (unsigned char)ifr->ifr_hwaddr.sa_data[1], (unsigned char)ifr->ifr_hwaddr.sa_data[2],
        (unsigned char)ifr->ifr_hwaddr.sa_data[3], (unsigned char)ifr->ifr_hwaddr.sa_data[4],
        (unsigned char)ifr->ifr_hwaddr.sa_data[5]);
    return std::string(mac_address);
  } else {
    return std::string();
  }
}

int cpuid(
    unsigned int type, unsigned int *eax, unsigned int *ebx, unsigned int *ecx, unsigned int *edx) {
  return __get_cpuid(type, eax, ebx, ecx, edx);
}

unsigned short cpuidHash() {
  unsigned int cpuinfo[4] = {0, 0, 0, 0};
  int ret = cpuid(0, &cpuinfo[0], &cpuinfo[1], &cpuinfo[2], &cpuinfo[3]);
  if (ret == 0) {
    return 0;
  }

  unsigned short hash = 0;
  unsigned int *ptr = (&cpuinfo[0]);
  for (unsigned int i = 0; i < 4; i++) {
    hash += (ptr[i] & 0xFFFF) + (ptr[i] >> 16);
  }
  return hash;
}

std::string cpuVendor() {
  unsigned int cpuinfo[4] = {0, 0, 0, 0};
  int ret = cpuid(0, &cpuinfo[0], &cpuinfo[1], &cpuinfo[2], &cpuinfo[3]);
  if (ret == 0) {
    return "unknown";
  }

  char vendor[16];
  *(unsigned int *)&vendor[0] = cpuinfo[1];
  *(unsigned int *)&vendor[4] = cpuinfo[3];
  *(unsigned int *)&vendor[8] = cpuinfo[2];
  vendor[12] = '\0';
  return std::string(vendor, strlen(vendor));
}

std::string cpuBrand() {
  unsigned int cpuinfo[4] = {0, 0, 0, 0};
  int ret = cpuid(0x80000000U, &cpuinfo[0], &cpuinfo[1], &cpuinfo[2], &cpuinfo[3]);
  if (ret == 0) {
    return "unknown";
  }

  if (cpuinfo[0] < 0x80000004U) {
    return "unknown";
  }

  // Function 80000002h, 80000003h, 80000004h: Processor Brand String
  char brand[64];
  cpuid(
      0x80000002U, (unsigned int *)&brand[0], (unsigned int *)&brand[4], (unsigned int *)&brand[8],
      (unsigned int *)&brand[12]);
  cpuid(
      0x80000003U, (unsigned int *)&brand[16], (unsigned int *)&brand[20],
      (unsigned int *)&brand[24], (unsigned int *)&brand[28]);
  cpuid(
      0x80000004U, (unsigned int *)&brand[32], (unsigned int *)&brand[36],
      (unsigned int *)&brand[40], (unsigned int *)&brand[44]);
  brand[48] = '\0';
  return std::string(brand, strlen(brand));
}

std::string etcMachineId() {
  std::ifstream fs("/etc/machine-id");
  if (!fs.is_open()) {
    return "";
  }

  char line[128];
  fs.getline(line, sizeof(line));
  return std::string(line);
}

std::string machineId() {
  std::stringstream stream;
  stream << etcMachineId();
  stream << machineName();
  stream << cpuidHash();
  stream << macAdrress();
  auto s = stream.str();

  std::string result;
  if (!RsaUtil::sha256(s, &result)) {
    return "";
  }
  return result;
}

}  // namespace license_cxx
