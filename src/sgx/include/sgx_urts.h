#ifndef _SGX_URTS_H_
#define _SGX_URTS_H_

typedef unsigned int sgx_enclave_id_t;
typedef unsigned int sgx_status_t;
#define SGX_SUCCESS 0
#define SGX_ERROR_UNEXPECTED 1

sgx_status_t sgx_create_enclave(const char *file_name, int debug, int *launch_token, int *launch_token_updated, sgx_enclave_id_t *enclave_id, int *misc_attr);
sgx_status_t sgx_destroy_enclave(sgx_enclave_id_t enclave_id);

#endif
