#ifndef ENCLAVE_U_H__
#define ENCLAVE_U_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include <string.h>
#include "sgx_edger8r.h" /* for sgx_satus_t etc. */

#include "types.h"

#include <stdlib.h> /* for size_t */

#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif

void SGX_UBRIDGE(SGX_NOCONVENTION, print, (const char* string));
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_print_string, (const char* str));
void SGX_UBRIDGE(SGX_NOCONVENTION, insert_af_record, (const char* record_str));
void SGX_UBRIDGE(SGX_CDECL, sgx_oc_cpuidex, (int cpuinfo[4], int leaf, int subleaf));
int SGX_UBRIDGE(SGX_CDECL, sgx_thread_wait_untrusted_event_ocall, (const void* self));
int SGX_UBRIDGE(SGX_CDECL, sgx_thread_set_untrusted_event_ocall, (const void* waiter));
int SGX_UBRIDGE(SGX_CDECL, sgx_thread_setwait_untrusted_events_ocall, (const void* waiter, const void* self));
int SGX_UBRIDGE(SGX_CDECL, sgx_thread_set_multiple_untrusted_events_ocall, (const void** waiters, size_t total));

sgx_status_t process_case_data(sgx_enclave_id_t eid, char* input, int len_input);
sgx_status_t process_control_data(sgx_enclave_id_t eid, char* input, int len_input);
sgx_status_t compute(sgx_enclave_id_t eid, int* lengths, int len_output);
sgx_status_t writeOutput(sgx_enclave_id_t eid, char* chi_str_param, char* af_str, int chi_length, int af_length);
sgx_status_t populateGroupSize(sgx_enclave_id_t eid, int* NGroupcase_fromApp, int* NGroupcontrol_fromAPP, int* K);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
