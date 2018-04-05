#include "Enclave_u.h"
#include <errno.h>

typedef struct ms_process_case_data_t {
	char* ms_input;
	int ms_len_input;
} ms_process_case_data_t;

typedef struct ms_process_control_data_t {
	char* ms_input;
	int ms_len_input;
} ms_process_control_data_t;

typedef struct ms_compute_t {
	int* ms_lengths;
	int ms_len_output;
} ms_compute_t;

typedef struct ms_writeOutput_t {
	char* ms_chi_str_param;
	char* ms_af_str;
	int ms_chi_length;
	int ms_af_length;
} ms_writeOutput_t;

typedef struct ms_populateGroupSize_t {
	int* ms_NGroupcase_fromApp;
	int* ms_NGroupcontrol_fromAPP;
	int* ms_K;
} ms_populateGroupSize_t;

typedef struct ms_print_t {
	char* ms_string;
} ms_print_t;

typedef struct ms_ocall_print_string_t {
	char* ms_str;
} ms_ocall_print_string_t;

typedef struct ms_insert_af_record_t {
	char* ms_record_str;
} ms_insert_af_record_t;

typedef struct ms_sgx_oc_cpuidex_t {
	int* ms_cpuinfo;
	int ms_leaf;
	int ms_subleaf;
} ms_sgx_oc_cpuidex_t;

typedef struct ms_sgx_thread_wait_untrusted_event_ocall_t {
	int ms_retval;
	void* ms_self;
} ms_sgx_thread_wait_untrusted_event_ocall_t;

typedef struct ms_sgx_thread_set_untrusted_event_ocall_t {
	int ms_retval;
	void* ms_waiter;
} ms_sgx_thread_set_untrusted_event_ocall_t;

typedef struct ms_sgx_thread_setwait_untrusted_events_ocall_t {
	int ms_retval;
	void* ms_waiter;
	void* ms_self;
} ms_sgx_thread_setwait_untrusted_events_ocall_t;

typedef struct ms_sgx_thread_set_multiple_untrusted_events_ocall_t {
	int ms_retval;
	void** ms_waiters;
	size_t ms_total;
} ms_sgx_thread_set_multiple_untrusted_events_ocall_t;

static sgx_status_t SGX_CDECL Enclave_print(void* pms)
{
	ms_print_t* ms = SGX_CAST(ms_print_t*, pms);
	print((const char*)ms->ms_string);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_print_string(void* pms)
{
	ms_ocall_print_string_t* ms = SGX_CAST(ms_ocall_print_string_t*, pms);
	ocall_print_string((const char*)ms->ms_str);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_insert_af_record(void* pms)
{
	ms_insert_af_record_t* ms = SGX_CAST(ms_insert_af_record_t*, pms);
	insert_af_record((const char*)ms->ms_record_str);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_sgx_oc_cpuidex(void* pms)
{
	ms_sgx_oc_cpuidex_t* ms = SGX_CAST(ms_sgx_oc_cpuidex_t*, pms);
	sgx_oc_cpuidex(ms->ms_cpuinfo, ms->ms_leaf, ms->ms_subleaf);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_sgx_thread_wait_untrusted_event_ocall(void* pms)
{
	ms_sgx_thread_wait_untrusted_event_ocall_t* ms = SGX_CAST(ms_sgx_thread_wait_untrusted_event_ocall_t*, pms);
	ms->ms_retval = sgx_thread_wait_untrusted_event_ocall((const void*)ms->ms_self);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_sgx_thread_set_untrusted_event_ocall(void* pms)
{
	ms_sgx_thread_set_untrusted_event_ocall_t* ms = SGX_CAST(ms_sgx_thread_set_untrusted_event_ocall_t*, pms);
	ms->ms_retval = sgx_thread_set_untrusted_event_ocall((const void*)ms->ms_waiter);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_sgx_thread_setwait_untrusted_events_ocall(void* pms)
{
	ms_sgx_thread_setwait_untrusted_events_ocall_t* ms = SGX_CAST(ms_sgx_thread_setwait_untrusted_events_ocall_t*, pms);
	ms->ms_retval = sgx_thread_setwait_untrusted_events_ocall((const void*)ms->ms_waiter, (const void*)ms->ms_self);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_sgx_thread_set_multiple_untrusted_events_ocall(void* pms)
{
	ms_sgx_thread_set_multiple_untrusted_events_ocall_t* ms = SGX_CAST(ms_sgx_thread_set_multiple_untrusted_events_ocall_t*, pms);
	ms->ms_retval = sgx_thread_set_multiple_untrusted_events_ocall((const void**)ms->ms_waiters, ms->ms_total);

	return SGX_SUCCESS;
}

static const struct {
	size_t nr_ocall;
	void * table[8];
} ocall_table_Enclave = {
	8,
	{
		(void*)Enclave_print,
		(void*)Enclave_ocall_print_string,
		(void*)Enclave_insert_af_record,
		(void*)Enclave_sgx_oc_cpuidex,
		(void*)Enclave_sgx_thread_wait_untrusted_event_ocall,
		(void*)Enclave_sgx_thread_set_untrusted_event_ocall,
		(void*)Enclave_sgx_thread_setwait_untrusted_events_ocall,
		(void*)Enclave_sgx_thread_set_multiple_untrusted_events_ocall,
	}
};
sgx_status_t process_case_data(sgx_enclave_id_t eid, char* input, int len_input)
{
	sgx_status_t status;
	ms_process_case_data_t ms;
	ms.ms_input = input;
	ms.ms_len_input = len_input;
	status = sgx_ecall(eid, 0, &ocall_table_Enclave, &ms);
	return status;
}

sgx_status_t process_control_data(sgx_enclave_id_t eid, char* input, int len_input)
{
	sgx_status_t status;
	ms_process_control_data_t ms;
	ms.ms_input = input;
	ms.ms_len_input = len_input;
	status = sgx_ecall(eid, 1, &ocall_table_Enclave, &ms);
	return status;
}

sgx_status_t compute(sgx_enclave_id_t eid, int* lengths, int len_output)
{
	sgx_status_t status;
	ms_compute_t ms;
	ms.ms_lengths = lengths;
	ms.ms_len_output = len_output;
	status = sgx_ecall(eid, 2, &ocall_table_Enclave, &ms);
	return status;
}

sgx_status_t writeOutput(sgx_enclave_id_t eid, char* chi_str_param, char* af_str, int chi_length, int af_length)
{
	sgx_status_t status;
	ms_writeOutput_t ms;
	ms.ms_chi_str_param = chi_str_param;
	ms.ms_af_str = af_str;
	ms.ms_chi_length = chi_length;
	ms.ms_af_length = af_length;
	status = sgx_ecall(eid, 3, &ocall_table_Enclave, &ms);
	return status;
}

sgx_status_t populateGroupSize(sgx_enclave_id_t eid, int* NGroupcase_fromApp, int* NGroupcontrol_fromAPP, int* K)
{
	sgx_status_t status;
	ms_populateGroupSize_t ms;
	ms.ms_NGroupcase_fromApp = NGroupcase_fromApp;
	ms.ms_NGroupcontrol_fromAPP = NGroupcontrol_fromAPP;
	ms.ms_K = K;
	status = sgx_ecall(eid, 4, &ocall_table_Enclave, &ms);
	return status;
}

