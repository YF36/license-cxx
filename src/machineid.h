/*
 * Author: yf36
 * License: BSD
 */

#ifndef LICENCE_CXX_MACHINEID_H_
#define LICENCE_CXX_MACHINEID_H_

#include <string>

namespace license_cxx {

std::string etcMachineId();
std::string machineName();
std::string cpuVendor();
std::string cpuBrand();
std::string macAdrress();
unsigned short cpuidHash();

std::string machineId();

}  // namespace license_cxx

#endif  // LICENCE_CXX_MACHINEID_H_
