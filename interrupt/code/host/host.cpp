#include <edge_call.h>
#include <keystone.h>
#include <sm/src/enclave.h>
#include <runtime/call/syscall.c>
#include <iostream>
#include <fstream>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <unistd.h>
#include <cstdio>
#include <sstream>
#include <iomanip>
#include <string>
#include <cstring>
#include "Memory.hpp"
#include "ElfFile.hpp"

enclave_id *enclave_eid;
struct sbi_trap_regs *host_regs;
char buf[4096];
int fd_clientsock;

unsigned long
print_string(char* str);
void
print_string_wrapper(void* buffer);
#define OCALL_PRINT_STRING 1

unsigned long print_string(char* str) {
  return printf("Enclave said: \"%s\"\n", str);
}

void print_string_wrapper(void* buffer) {
  struct edge_call* edge_call = (struct edge_call*)buffer;
  uintptr_t call_args;
  unsigned long ret_val;
  size_t arg_len;
  if (edge_call_args_ptr(edge_call, &call_args, &arg_len) != 0) {
    edge_call->return_data.call_status = CALL_STATUS_BAD_OFFSET;
    return;
  }

  ret_val = print_string((char*)call_args);

  uintptr_t data_section = edge_call_data_ptr();
  memcpy((void*)data_section, &ret_val, sizeof(unsigned long));
  if (edge_call_setup_ret(
          edge_call, (void*)data_section, sizeof(unsigned long))) {
    edge_call->return_data.call_status = CALL_STATUS_BAD_PTR;
  } else {
    edge_call->return_data.call_status = CALL_STATUS_OK;
  }
  return;
}

unsigned long pass_message() {
  read(fd_clientsock, buf, sizeof(size_t));
  edge_syscall msg;
  msg.syscall_num = HOST_INT;
  msg.data = buf;

  struct sbi_trap_regs *enclave_regs; = handle_interrupt(&msg, strlen(str), enclave_eid);

  unsigned long ret = resume_enclave(enclave_regs, enclave_eid);
  return ret;
}

void init_network_wait(){

  int fd_sock;
  struct sockaddr_in server_addr;

  fd_sock = socket(AF_INET, SOCK_STREAM, 0);
  if (fd_sock < 0){
    printf("Failed to open socket\n");
    exit(-1);
  }
  memset(&server_addr, 0, sizeof(server_addr));
  server_addr.sin_family = AF_INET;
  server_addr.sin_addr.s_addr = INADDR_ANY;
  server_addr.sin_port = htons(8067);
  if( bind(fd_sock, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0){
    printf("Failed to bind socket\n");
    exit(-1);
  }
  listen(fd_sock,2);

  struct sockaddr_in client_addr;
  socklen_t client_len = sizeof(client_addr);
  fd_clientsock = accept(fd_sock, (struct sockaddr*)&client_addr, &client_len);
  if (fd_clientsock < 0){
    printf("No valid client socket\n");
    exit(-1);
  }
}


int main(int argc, char** argv) {
  init_network_wait();

  Keystone::PhysicalEnclaveMemory pMemory = new PhysicalEnclaveMemory();
  Keystone::KeystoneDevice pDevice = new KeystoneDevice();

  Keystone::ElfFile* enclaveFile = new ElfFile(argc[1]);
  Keystone::ElfFile* runtimeFile = new ElfFile(argc[2]);
  Keystone::ElfFile* loaderFile = new ElfFile(argc[3]);

  if (!pDevice->initDevice(params)) {
    destroy();
    return Error::DeviceInitFailure;
  }

  Keystone::ElfFile* elfFiles[3] = {enclaveFile, runtimeFile, loaderFile};
  size_t requiredPages = calculate_required_pages(elfFiles, 3);

  if (!prepareEnclaveMemory(requiredPages, alternatePhysAddr)) {
    destroy();
  }
  if (!pMemory->allocUtm(params.getUntrustedSize())) {
    destroy();
  }
	
  copyFile((uintptr_t) loaderFile->getPtr(), loaderFile->getFileSize());

  pMemory->startRuntimeMem();
  copyFile((uintptr_t) runtimeFile->getPtr(), runtimeFile->getFileSize());

  pMemory->startEappMem();
  copyFile((uintptr_t) enclaveFile->getPtr(), enclaveFile->getFileSize());

  pMemory->startFreeMem();

  if (pDevice->finalize(
          pMemory->getRuntimePhysAddr(), pMemory->getEappPhysAddr(),
          pMemory->getFreePhysAddr(), params.getFreeMemSize()) != Error::Success) {
    destroy();
  }
  if (!mapUntrusted(params.getUntrustedSize())) {
    destroy();
  }
  delete enclaveFile;
  delete runtimeFile;
  delete loaderFile;

  register_call(OCALL_PRINT_STRING, print_string_wrapper);
  struct keystone_sbi_create_t * create_args = (*keystone_sbi_create_t) argv;
  unsigned long ret = create_enclave(enclave_eid, &create_args);
  edge_call_init_internals((uintptr_t)enclave.getSharedBuffer(), enclave.getSharedBufferSize());
  unsigned long ret = run_enclave(host_regs, enclave_eid);
  return 0;
}