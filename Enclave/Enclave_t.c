#include "Enclave_t.h"

#include "sgx_trts.h" /* for sgx_ocalloc, sgx_is_outside_enclave */

#include <errno.h>
#include <string.h> /* for memcpy etc */
#include <stdlib.h> /* for malloc/free etc */

#define CHECK_REF_POINTER(ptr, siz) do {	\
	if (!(ptr) || ! sgx_is_outside_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define CHECK_UNIQUE_POINTER(ptr, siz) do {	\
	if ((ptr) && ! sgx_is_outside_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)


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

static sgx_status_t SGX_CDECL sgx_process_case_data(void* pms)
{
	ms_process_case_data_t* ms = SGX_CAST(ms_process_case_data_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	char* _tmp_input = ms->ms_input;
	int _tmp_len_input = ms->ms_len_input;
	size_t _len_input = _tmp_len_input;
	char* _in_input = NULL;

	CHECK_REF_POINTER(pms, sizeof(ms_process_case_data_t));
	CHECK_UNIQUE_POINTER(_tmp_input, _len_input);

	if (_tmp_input != NULL) {
		_in_input = (char*)malloc(_len_input);
		if (_in_input == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy(_in_input, _tmp_input, _len_input);
	}
	process_case_data(_in_input, _tmp_len_input);
err:
	if (_in_input) free(_in_input);

	return status;
}

static sgx_status_t SGX_CDECL sgx_process_control_data(void* pms)
{
	ms_process_control_data_t* ms = SGX_CAST(ms_process_control_data_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	char* _tmp_input = ms->ms_input;
	int _tmp_len_input = ms->ms_len_input;
	size_t _len_input = _tmp_len_input;
	char* _in_input = NULL;

	CHECK_REF_POINTER(pms, sizeof(ms_process_control_data_t));
	CHECK_UNIQUE_POINTER(_tmp_input, _len_input);

	if (_tmp_input != NULL) {
		_in_input = (char*)malloc(_len_input);
		if (_in_input == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy(_in_input, _tmp_input, _len_input);
	}
	process_control_data(_in_input, _tmp_len_input);
err:
	if (_in_input) free(_in_input);

	return status;
}

static sgx_status_t SGX_CDECL sgx_compute(void* pms)
{
	ms_compute_t* ms = SGX_CAST(ms_compute_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	int* _tmp_lengths = ms->ms_lengths;
	int _tmp_len_output = ms->ms_len_output;
	size_t _len_lengths = _tmp_len_output;
	int* _in_lengths = NULL;

	CHECK_REF_POINTER(pms, sizeof(ms_compute_t));
	CHECK_UNIQUE_POINTER(_tmp_lengths, _len_lengths);

	if (_tmp_lengths != NULL) {
		if ((_in_lengths = (int*)malloc(_len_lengths)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_lengths, 0, _len_lengths);
	}
	compute(_in_lengths, _tmp_len_output);
err:
	if (_in_lengths) {
		memcpy(_tmp_lengths, _in_lengths, _len_lengths);
		free(_in_lengths);
	}

	return status;
}

static sgx_status_t SGX_CDECL sgx_writeOutput(void* pms)
{
	ms_writeOutput_t* ms = SGX_CAST(ms_writeOutput_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	char* _tmp_chi_str_param = ms->ms_chi_str_param;
	int _tmp_chi_length = ms->ms_chi_length;
	size_t _len_chi_str_param = _tmp_chi_length;
	char* _in_chi_str_param = NULL;
	char* _tmp_af_str = ms->ms_af_str;
	int _tmp_af_length = ms->ms_af_length;
	size_t _len_af_str = _tmp_af_length;
	char* _in_af_str = NULL;

	CHECK_REF_POINTER(pms, sizeof(ms_writeOutput_t));
	CHECK_UNIQUE_POINTER(_tmp_chi_str_param, _len_chi_str_param);
	CHECK_UNIQUE_POINTER(_tmp_af_str, _len_af_str);

	if (_tmp_chi_str_param != NULL) {
		if ((_in_chi_str_param = (char*)malloc(_len_chi_str_param)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_chi_str_param, 0, _len_chi_str_param);
	}
	if (_tmp_af_str != NULL) {
		if ((_in_af_str = (char*)malloc(_len_af_str)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_af_str, 0, _len_af_str);
	}
	writeOutput(_in_chi_str_param, _in_af_str, _tmp_chi_length, _tmp_af_length);
err:
	if (_in_chi_str_param) {
		memcpy(_tmp_chi_str_param, _in_chi_str_param, _len_chi_str_param);
		free(_in_chi_str_param);
	}
	if (_in_af_str) {
		memcpy(_tmp_af_str, _in_af_str, _len_af_str);
		free(_in_af_str);
	}

	return status;
}

static sgx_status_t SGX_CDECL sgx_populateGroupSize(void* pms)
{
	ms_populateGroupSize_t* ms = SGX_CAST(ms_populateGroupSize_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	int* _tmp_NGroupcase_fromApp = ms->ms_NGroupcase_fromApp;
	size_t _len_NGroupcase_fromApp = sizeof(*_tmp_NGroupcase_fromApp);
	int* _in_NGroupcase_fromApp = NULL;
	int* _tmp_NGroupcontrol_fromAPP = ms->ms_NGroupcontrol_fromAPP;
	size_t _len_NGroupcontrol_fromAPP = sizeof(*_tmp_NGroupcontrol_fromAPP);
	int* _in_NGroupcontrol_fromAPP = NULL;
	int* _tmp_K = ms->ms_K;
	size_t _len_K = sizeof(*_tmp_K);
	int* _in_K = NULL;

	CHECK_REF_POINTER(pms, sizeof(ms_populateGroupSize_t));
	CHECK_UNIQUE_POINTER(_tmp_NGroupcase_fromApp, _len_NGroupcase_fromApp);
	CHECK_UNIQUE_POINTER(_tmp_NGroupcontrol_fromAPP, _len_NGroupcontrol_fromAPP);
	CHECK_UNIQUE_POINTER(_tmp_K, _len_K);

	if (_tmp_NGroupcase_fromApp != NULL) {
		_in_NGroupcase_fromApp = (int*)malloc(_len_NGroupcase_fromApp);
		if (_in_NGroupcase_fromApp == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy(_in_NGroupcase_fromApp, _tmp_NGroupcase_fromApp, _len_NGroupcase_fromApp);
	}
	if (_tmp_NGroupcontrol_fromAPP != NULL) {
		_in_NGroupcontrol_fromAPP = (int*)malloc(_len_NGroupcontrol_fromAPP);
		if (_in_NGroupcontrol_fromAPP == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy(_in_NGroupcontrol_fromAPP, _tmp_NGroupcontrol_fromAPP, _len_NGroupcontrol_fromAPP);
	}
	if (_tmp_K != NULL) {
		_in_K = (int*)malloc(_len_K);
		if (_in_K == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy(_in_K, _tmp_K, _len_K);
	}
	populateGroupSize(_in_NGroupcase_fromApp, _in_NGroupcontrol_fromAPP, _in_K);
err:
	if (_in_NGroupcase_fromApp) free(_in_NGroupcase_fromApp);
	if (_in_NGroupcontrol_fromAPP) free(_in_NGroupcontrol_fromAPP);
	if (_in_K) free(_in_K);

	return status;
}

SGX_EXTERNC const struct {
	size_t nr_ecall;
	struct {void* ecall_addr; uint8_t is_priv;} ecall_table[5];
} g_ecall_table = {
	5,
	{
		{(void*)(uintptr_t)sgx_process_case_data, 0},
		{(void*)(uintptr_t)sgx_process_control_data, 0},
		{(void*)(uintptr_t)sgx_compute, 0},
		{(void*)(uintptr_t)sgx_writeOutput, 0},
		{(void*)(uintptr_t)sgx_populateGroupSize, 0},
	}
};

SGX_EXTERNC const struct {
	size_t nr_ocall;
	uint8_t entry_table[8][5];
} g_dyn_entry_table = {
	8,
	{
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
	}
};


sgx_status_t SGX_CDECL print(const char* string)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_string = string ? strlen(string) + 1 : 0;

	ms_print_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_print_t);
	void *__tmp = NULL;

	ocalloc_size += (string != NULL && sgx_is_within_enclave(string, _len_string)) ? _len_string : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_print_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_print_t));

	if (string != NULL && sgx_is_within_enclave(string, _len_string)) {
		ms->ms_string = (char*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_string);
		memcpy((void*)ms->ms_string, string, _len_string);
	} else if (string == NULL) {
		ms->ms_string = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	status = sgx_ocall(0, ms);


	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_print_string(const char* str)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_str = str ? strlen(str) + 1 : 0;

	ms_ocall_print_string_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_print_string_t);
	void *__tmp = NULL;

	ocalloc_size += (str != NULL && sgx_is_within_enclave(str, _len_str)) ? _len_str : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_print_string_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_print_string_t));

	if (str != NULL && sgx_is_within_enclave(str, _len_str)) {
		ms->ms_str = (char*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_str);
		memcpy((void*)ms->ms_str, str, _len_str);
	} else if (str == NULL) {
		ms->ms_str = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	status = sgx_ocall(1, ms);


	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL insert_af_record(const char* record_str)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_record_str = record_str ? strlen(record_str) + 1 : 0;

	ms_insert_af_record_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_insert_af_record_t);
	void *__tmp = NULL;

	ocalloc_size += (record_str != NULL && sgx_is_within_enclave(record_str, _len_record_str)) ? _len_record_str : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_insert_af_record_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_insert_af_record_t));

	if (record_str != NULL && sgx_is_within_enclave(record_str, _len_record_str)) {
		ms->ms_record_str = (char*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_record_str);
		memcpy((void*)ms->ms_record_str, record_str, _len_record_str);
	} else if (record_str == NULL) {
		ms->ms_record_str = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	status = sgx_ocall(2, ms);


	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_oc_cpuidex(int cpuinfo[4], int leaf, int subleaf)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_cpuinfo = 4 * sizeof(*cpuinfo);

	ms_sgx_oc_cpuidex_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_oc_cpuidex_t);
	void *__tmp = NULL;

	ocalloc_size += (cpuinfo != NULL && sgx_is_within_enclave(cpuinfo, _len_cpuinfo)) ? _len_cpuinfo : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_oc_cpuidex_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_oc_cpuidex_t));

	if (cpuinfo != NULL && sgx_is_within_enclave(cpuinfo, _len_cpuinfo)) {
		ms->ms_cpuinfo = (int*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_cpuinfo);
		memcpy(ms->ms_cpuinfo, cpuinfo, _len_cpuinfo);
	} else if (cpuinfo == NULL) {
		ms->ms_cpuinfo = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_leaf = leaf;
	ms->ms_subleaf = subleaf;
	status = sgx_ocall(3, ms);

	if (cpuinfo) memcpy((void*)cpuinfo, ms->ms_cpuinfo, _len_cpuinfo);

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_thread_wait_untrusted_event_ocall(int* retval, const void* self)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_sgx_thread_wait_untrusted_event_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_thread_wait_untrusted_event_ocall_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_thread_wait_untrusted_event_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_thread_wait_untrusted_event_ocall_t));

	ms->ms_self = SGX_CAST(void*, self);
	status = sgx_ocall(4, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_thread_set_untrusted_event_ocall(int* retval, const void* waiter)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_sgx_thread_set_untrusted_event_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_thread_set_untrusted_event_ocall_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_thread_set_untrusted_event_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_thread_set_untrusted_event_ocall_t));

	ms->ms_waiter = SGX_CAST(void*, waiter);
	status = sgx_ocall(5, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_thread_setwait_untrusted_events_ocall(int* retval, const void* waiter, const void* self)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_sgx_thread_setwait_untrusted_events_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_thread_setwait_untrusted_events_ocall_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_thread_setwait_untrusted_events_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_thread_setwait_untrusted_events_ocall_t));

	ms->ms_waiter = SGX_CAST(void*, waiter);
	ms->ms_self = SGX_CAST(void*, self);
	status = sgx_ocall(6, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_thread_set_multiple_untrusted_events_ocall(int* retval, const void** waiters, size_t total)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_waiters = total * sizeof(*waiters);

	ms_sgx_thread_set_multiple_untrusted_events_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_thread_set_multiple_untrusted_events_ocall_t);
	void *__tmp = NULL;

	ocalloc_size += (waiters != NULL && sgx_is_within_enclave(waiters, _len_waiters)) ? _len_waiters : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_thread_set_multiple_untrusted_events_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_thread_set_multiple_untrusted_events_ocall_t));

	if (waiters != NULL && sgx_is_within_enclave(waiters, _len_waiters)) {
		ms->ms_waiters = (void**)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_waiters);
		memcpy((void*)ms->ms_waiters, waiters, _len_waiters);
	} else if (waiters == NULL) {
		ms->ms_waiters = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_total = total;
	status = sgx_ocall(7, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

