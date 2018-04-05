/*
 * Copyright (C) 2011-2017 Intel Corporation. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *   * Neither the name of Intel Corporation nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */



#include <cstring>
#include <string>
#include <sstream>
#include "stdlib.h"
#include "stdio.h"
#include "sgx_trts.h"
#include "sgx_thread.h"
#include "sgx_tseal.h"
#include <vector>
#include <map>
#include <set>
#include <math.h>
#include <algorithm>
#include "Rijndael.h"
#include <sstream>

#include "Enclave_t.h"

using namespace std;
#define Z_EPSILON 0.000001       /* accuracy of critz approximation */
#define Z_MAX 6.0            /* maximum meaningful z value */

#define        LOG_SQRT_PI     0.5723649429247000870717135 /* log (sqrt (pi)) */
#define        I_SQRT_PI       0.5641895835477562869480795 /* 1 / sqrt (pi) */
#define        BIGX           20.0         /* max value to represent exp (x) */
#define        ex(x)             (((x) < -BIGX) ? 0.0 : exp (x))

void computation();
//CRijndael oRijndael;
void printf(const char *fmt, ...);
uint32_t* g_secret;
//char* mysecret = "abcdefghijklmnop";
//sgx_thread_mutex_t g_mutex = SGX_THREAD_MUTEX_INITIALIZER;

char* vcf_file_input;//=(char*)malloc(2926273 * sizeof(char));
vector<std::string> vcf_blocks;

char* case_string;
vector<std::string> case_string_vector;

char* control_string;
vector<std::string> control_string_vector;

int NGroupcase, NGroupcontrol,K;

std::map<std::string, int> dsnpcase;
std::map<std::string, int> dsnpcontrol;
set<std::string> lsnp;
vector<std::string> laf;
vector<std::string> lfchis;


std::string chis_str = "";
std::string af_str = "";

uint8_t* testSealedData;
//custom comparator for sorting records based on chr position
struct {
        bool operator()(std::string a, std::string b) const
        {   
            //char* a_str; char* b_str; printf("line %d \n", 85);
            char* a_str = (char*)malloc(strlen(a.c_str()) + 1);  
            char* b_str = (char*)malloc(strlen(b.c_str()) + 1);  
            //memcpy(a_str, a.c_str(), strlen(a.c_str())); printf("line %d \n", 86);
            //memcpy(b_str, b.c_str(), strlen(b.c_str())); printf("line %d \n", 87);
            strncpy(a_str, a.c_str(), strlen(a.c_str())); 
            strncpy(b_str, b.c_str(), strlen(b.c_str())); 

            char* a_ptr; char* b_ptr; 
            a_ptr = strtok(a_str, "-");  // First token is chr number
	    a_ptr = strtok(NULL, "-");   //second token is chr position 

            std::string aPos_str = std::string(a_ptr); 
            int aPos = atoi(aPos_str.c_str()); 

            b_ptr = strtok(b_str, "-");   // First token is chr number
	    b_ptr = strtok(NULL, "-");    //second token is chr position 

            std::string bPos_str = std::string(b_ptr); 
            int bPos = atoi(bPos_str.c_str()); 

            free(a_str); 
            free(b_str); 
            return aPos < bPos;
        }   
       } comparatorAF;
//custom comparator for sorting records based on P-value
struct {
        bool operator()(std::string a, std::string b) const
        {   int last_pos_a = a.find_last_of("-"); 
            double Pa = atof(a.substr(last_pos_a + 1).c_str()); 
    
            int last_pos_b = b.find_last_of("-");  
            double Pb = atof(b.substr(last_pos_b + 1).c_str());  
            return Pa < Pb;
        }   
       } comparatorChis;


double poz (double z)           /*VAR returns cumulative probability from -oo to z */ 
//double z;        /*VAR normal z value */
       {
       double  y, x, w;
       
       if (z == 0.0)
               x = 0.0;
       else
               {
               y = 0.5 * fabs (z);
               if (y >= (Z_MAX * 0.5))
                       x = 1.0;
               else if (y < 1.0)
                       {
                       w = y*y;
                       x = ((((((((0.000124818987 * w
                               -0.001075204047) * w +0.005198775019) * w
                               -0.019198292004) * w +0.059054035642) * w
                               -0.151968751364) * w +0.319152932694) * w
                               -0.531923007300) * w +0.797884560593) * y * 2.0;
                       }
               else
                       {
                       y -= 2.0;
                       x = (((((((((((((-0.000045255659 * y
                               +0.000152529290) * y -0.000019538132) * y
                               -0.000676904986) * y +0.001390604284) * y
                               -0.000794620820) * y -0.002034254874) * y
                               +0.006549791214) * y -0.010557625006) * y
                               +0.011630447319) * y -0.009279453341) * y
                               +0.005353579108) * y -0.002141268741) * y
                               +0.000535310849) * y +0.999936657524;
                       }
               }
       return (z > 0.0 ? ((x + 1.0) * 0.5) : ((1.0 - x) * 0.5));
       }

double pochisq(double x, int df)
//double x;       /* obtained chi-square value */
//int    df;      /* degrees of freedom */
       {
       double  a, y, s;
       double  e, c, z;
       //double  poz ();   /* computes probability of normal z score */
       int     even;     /* true if df is an even number */
       
       if (x <= 0.0 || df < 1)
               return (1.0);
       
       a = 0.5 * x;
       even = (2*(df/2)) == df;
       if (df > 1)
               y = ex (-a);
       s = (even ? y : (2.0 * poz(-sqrt(x))));
       if (df > 2)

               {
               x = 0.5 * (df - 1.0);
               z = (even ? 1.0 : 0.5);
               if (a > BIGX)
                       {
                       e = (even ? 0.0 : LOG_SQRT_PI);
                       c = log (a);
                       while (z <= x)
                               {
                               e = log (z) + e;
                               s += ex (c*z-a-e);
                               z += 1.0;
                               }
                       return (s);
                       }
               else
                       {
                       e = (even ? 1.0 : (I_SQRT_PI / sqrt (a)));
                       c = 0.0;
                       while (z <= x)
                               {
                               e = e * (a / z);
                               c = c + e;
                               z += 1.0;
                               }
                       return (c * y + s);
                       }
               }
       else
               return (s);
       }


void printf(const char *fmt, ...)
{
    char buf[BUFSIZ] = {'\0'};
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, BUFSIZ, fmt, ap);
    va_end(ap);
    ocall_print_string(buf);
}

//Function to convert unsigned char to string of length 2
void Char2Hex(unsigned char ch, char* szHex)
{
	unsigned char byte[2];
	byte[0] = ch/16;
	byte[1] = ch%16;
	for(int i=0; i<2; i++)
	{
		if(byte[i] >= 0 && byte[i] <= 9)
			szHex[i] = '0' + byte[i];
		else
			szHex[i] = 'A' + byte[i] - 10;
	}
	szHex[2] = 0;
}

//Function to convert string of length 2 to unsigned char
void Hex2Char(char const* szHex, unsigned char& rch)
{
	rch = 0;
	for(int i=0; i<2; i++)
	{
		if(*(szHex + i) >='0' && *(szHex + i) <= '9')
			rch = (rch << 4) + (*(szHex + i) - '0');
		else if(*(szHex + i) >='A' && *(szHex + i) <= 'F')
			rch = (rch << 4) + (*(szHex + i) - 'A' + 10);
		else
			break;
	}
}    

//Function to convert string of chars to string of unsigned chars
void HexStr2CharStr(char const* pszHexStr, unsigned char* pucCharStr, int iSize)
{
	int i;
	unsigned char ch;
	for(i=0; i<iSize; i++)
	{
		Hex2Char(pszHexStr+2*i, ch);
		pucCharStr[i] = ch;
	}
}

static inline void free_allocated_memory(void *pointer)
{
    if(pointer != NULL)
    {
        free(pointer);
        pointer = NULL;
    }
}

void process_case_data(char* input, int len_input)
{
    //printf("inside enclave case processing routine %d \n", len_input);
    case_string = (char*)malloc(strlen(input) + 1); 
   
    memcpy(case_string, input, strlen(input) - 1); 
    case_string[strlen(input) - 1] = '\0'; 


    CRijndael oRijndael;
    oRijndael.MakeKey("1234567890123456", "1111111122222222", 16, 16);
    int blk_length = 64;
    
    
    char* ch;
    std::string container;
    int track = 0;
    ch = strtok(case_string, ",");
    while (ch != NULL) {
      std::string container = std::string(ch);
      //printf("in enclave %d %s \n", strlen(container.c_str()), container.c_str());


      char case_string_to_decrypt[blk_length +1];
      char decrypted_case_string[blk_length + 1];
      HexStr2CharStr(container.c_str(), (unsigned char*)case_string_to_decrypt, blk_length);
      memset(decrypted_case_string, 0, blk_length + 1);
      oRijndael.ResetChain();
      oRijndael.Decrypt(case_string_to_decrypt, decrypted_case_string, blk_length, CRijndael::CBC);

      std::string decrypted_record = std::string(decrypted_case_string);
      //printf("in enclave %d %s \n", strlen(decrypted_record.c_str()), decrypted_record.c_str());


      int last_pos = decrypted_record.find_last_of("-");
      std::string key = decrypted_record.substr(0, last_pos);
      int cnt = atoi(decrypted_record.substr(last_pos + 1).c_str());
      dsnpcase[key] += cnt;
      lsnp.insert(key);
  
       if(key == "1")
      {
         printf("for case 1 last_pos %d \n", last_pos); 
         printf("%s \n", ch);
         printf("track %d \n", track);
      }
      //strncpy(container.c_str(), ch, strlen(ch));
      //case_string_vector.push_back(container);
      //printf("%s \n", ch);
      ch = strtok(NULL, ",");
      container.clear();
      decrypted_record.clear();
    } 
    

    free(case_string);
    
}


void process_control_data(char* input, int len_input)
{
    //printf("inside enclave control processing routine %d \n", len_input);
    control_string = (char*)malloc(strlen(input) + 1); 
   
    memcpy(control_string, input, strlen(input) - 1); 
    control_string[strlen(input) - 1] = '\0'; 

    //CRijndael oRijndael; printf("line %d \n", 723);
    //oRijndael.MakeKey("1234567890123456", "1111111122222222", 16, 16); printf("line %d \n", 724);
    //int blk_length = 32; printf("line %d \n", 725);

    CRijndael oRijndael;
    oRijndael.MakeKey("1234567890123456", "1111111122222222", 16, 16);
    int blk_length = 64;
    
    
    char* ch;
    std::string container;
    int track = 0;
    ch = strtok(control_string, ",");
    while (ch != NULL) {
      std::string container = std::string(ch);
      //printf("in enclave %d %s \n", strlen(container.c_str()), container.c_str());


      char control_string_to_decrypt[blk_length +1];
      char decrypted_control_string[blk_length + 1];
      HexStr2CharStr(container.c_str(), (unsigned char*)control_string_to_decrypt, blk_length);
      memset(decrypted_control_string, 0, blk_length + 1);
      oRijndael.ResetChain();
      oRijndael.Decrypt(control_string_to_decrypt, decrypted_control_string, blk_length, CRijndael::CBC);

      std::string decrypted_record = std::string(decrypted_control_string);
      //printf("in enclave %d %s \n", strlen(decrypted_record.c_str()), decrypted_record.c_str());


      int last_pos = decrypted_record.find_last_of("-");
      std::string key = decrypted_record.substr(0, last_pos);
      int cnt = atoi(decrypted_record.substr(last_pos + 1).c_str());
      dsnpcontrol[key] += cnt;
      lsnp.insert(key);
  
       if(key == "1")
      {
         printf("for control 1 last_pos %d \n", last_pos); 
         printf("%s \n", ch);
         printf("track %d \n", track);
      }
      //strncpy(container.c_str(), ch, strlen(ch));
      //case_string_vector.push_back(container);
      //printf("%s \n", ch);
      ch = strtok(NULL, ",");
      container.clear();
      decrypted_record.clear();
    } 
    

    free(control_string);
}    


void populateGroupSize(int* NGroupcase_fromApp, int* NGroupcontrol_fromAPP, int* top_k)
{
    NGroupcase = *NGroupcase_fromApp;
    NGroupcontrol = *NGroupcontrol_fromAPP;
    K = *top_k;
}


void compute(int* lengths, int len_output)
{
   // input: vcf_file_input
   double pseudo = pow(10, -290); 
   int Ng1 = NGroupcontrol * 2;
   int Ng2 = NGroupcase * 2;
   
   set<std::string>::iterator setIt; 
   
   for(setIt = lsnp.begin(); setIt != lsnp.end(); ++setIt)
    {
       //cout << (*setIt) << endl;
       float ng1alt, ng2alt;
       if(dsnpcontrol.find(*setIt) == dsnpcontrol.end())
       {
          ng1alt = 0; //printf("line %d \n", 529);
       }
       else
       {
          ng1alt = dsnpcontrol[*setIt] * 1.0; //printf("line %d \n", 534);
       }


       if(dsnpcase.find(*setIt) == dsnpcase.end())
       {
          ng2alt = 0;  //printf("line %d \n", 540);
       }
       else
       {
          ng2alt = dsnpcase[*setIt] * 1.0; // printf("line %d \n", 544);
       }
    
       //calculate allele frequency 
       double faf = (ng1alt + ng2alt) / (double) (Ng1 + Ng2); // printf("line %d \n", 548);
       //laf.push_back((*setIt) + "-" + std::to_string(faf));   // printf("line %d \n", 549);
       insert_af_record(((*setIt) + "-" + std::to_string(faf)).c_str());
       
       // add pseudo cnt in case division error
       ng1alt += pseudo;
       ng2alt += pseudo;
       double ng1ref = Ng1 - ng1alt;
       double ng2ref = Ng2 - ng2alt;
       int Nsample = Ng1 + Ng2;// printf("line %d \n", 556);
       
       double Nref = ng1ref + ng2ref;
       double Nalt = ng1alt + ng2alt;

       vector<double> lobserved;
       vector<double> lexpected;
       
       double eg1Ref = Ng1*Nref/(double)(Nsample); //printf("line %d \n", 564);
       double eg2Ref = Ng2*Nref/(double)(Nsample);
       double eg1Alt = Ng1*Nalt/(double)(Nsample);
       double eg2Alt = Ng2*Nalt/(double)(Nsample); 

       lobserved.push_back(ng1ref);
       lobserved.push_back(ng2ref);
       lobserved.push_back(ng1alt);
       lobserved.push_back(ng2alt);

       lexpected.push_back(eg1Ref);
       lexpected.push_back(eg2Ref);
       lexpected.push_back(eg1Alt);
       lexpected.push_back(eg2Alt);
       
       double fchis = 0;
       
       fchis += pow((lobserved.at(0) - lexpected.at(0)), 2) / lexpected.at(0); //printf("line %d \n", 581);
       fchis += pow((lobserved.at(1) - lexpected.at(1)), 2) / lexpected.at(1);
       fchis += pow((lobserved.at(2) - lexpected.at(2)), 2) / lexpected.at(2);
       fchis += pow((lobserved.at(3) - lexpected.at(3)), 2) / lexpected.at(3);

       double p_value = pochisq(fchis, 3);  //printf("line %d \n", 586);
       //double p_value = chisqr(5, fchis);
       //double p_value = getChiSqPValue(4, fchis);
       if(!isnan(p_value))
         lfchis.push_back((*setIt) + "-" + std::to_string(p_value));
       //cout << p_value << endl;
       //ostringstream buffer;
       double abc = 3.14;
       std::string abc_str = std::to_string(abc); 
        
    }
    
    //std::sort(laf.begin(), laf.end(), comparatorAF); printf("line %d \n", 598);
    std::sort(lfchis.begin(), lfchis.end(), comparatorChis); 

    //printf("first p-value record is %s", (*lfchis.begin()).c_str()); 
    //printf("first AF record is %s", (*laf.begin()).c_str()); 
    //printf("first entry of lsnp %s \n", (*lsnp.begin()).c_str());
    //printf("here \n");
    //std::string chis_str = ""; printf("line %d \n", 616);
    for(int i = 0; i < K; i++)
    {
       chis_str = chis_str + lfchis.at(i);
       chis_str = chis_str + "\n";
    }
     
    lengths[0] = strlen(chis_str.c_str());
    //output_chis((char*)chis_str.c_str(), strlen(chis_str.c_str())); printf("line %d \n", 623);
    
    //std::string af_str = ""; printf("line %d \n", 625);

    vector<std::string>::iterator It; 
    
    int appended_string = 0;
    /*
    for(It = laf.begin(); It != laf.end(); It++)
    { 
       af_str = af_str + (*It);
       af_str = af_str + "\n";
       //appended_string++;
       //printf("appended string %d \n", appended_string);
    }
    */
    //printf("line %d \n", 634);
    
    /*
    for(int j = 0; j < 3500; j++)
    {
       af_str = af_str + laf.at(j);
       af_str = af_str + "\n";
    }
    */
    //for (auto const& s : laf) { af_str = af_str + s + "\n"; }
    
    lengths[1] = 10000;//strlen(af_str.c_str());
    //printf("chis str length in enclave %d \n", lengths[0]);
    //printf("af str length in enclave %d \n", lengths[1]);
    //printf("before calling af file ocall. size is %d \n", strlen(af_str.c_str()));
     
    //output_af((char*)af_str.c_str(), strlen(af_str.c_str())); printf("line %d \n", 642);
    
}

void writeOutput(char* chi_str_param, char* af_str_param, int chi_length, int af_length)
{
   //write output
    //char* af_str_dest = (char*)malloc(strlen(af_str.c_str()) + 1);  printf("line %d \n", 649);
    
    memset(chi_str_param, 0, chi_length);
    memcpy(chi_str_param, chis_str.c_str(), chi_length - 1); 
    chi_str_param[chi_length - 1] = '\0';
    //printf("in write output enclave function %d %s \n", strlen(chi_str_param), chi_str_param);
    //memcpy(af_str_param, af_str.c_str(), af_length - 1); printf("line %d \n", 650);
    //af_str_param[af_length - 1] = '\0';
}


/*
void compute_sealed_data_size(int* mac_len, int* data_len, int* sealed_size)
{
    
    *sealed_size = sgx_calc_sealed_data_size(*mac_len, *data_len);
    return;
}     
void seal_vcf_string(char* input, uint8_t* output, int len_input, int len_output)
{
    printf("inside enclave %d \n", strlen(input));
    //printf("%s \n", input);
    //char* input_vcf_char = new char[len_input + 1];
    char* data_to_seal = (char*)malloc(strlen(input) + 1);
    //vcf_file_input = (char*)malloc(strlen(input) + 1);
    //input = (char*)malloc(strlen(input) + 1);
    memcpy(data_to_seal, input, strlen(input) - 1);
    data_to_seal[strlen(input) - 1] = '\0';

    //Seal the data
    uint32_t sealed_len = sizeof(sgx_sealed_data_t) + sizeof(data_to_seal);//sgx_calc_sealed_data_size(0, strlen(input) + 1);// // = //
    printf("sealed length is %d \n", sealed_len);
    
    int  sealed_size = sgx_calc_sealed_data_size(0, strlen(input) + 1);
    printf("sgx_calc_sealed_data_size %d \n", sealed_size);
  
    uint8_t *plain_text = NULL;
    uint32_t plain_text_length = 0;
    uint8_t *temp_sealed_buf = (uint8_t *)malloc(sealed_len);
    sgx_status_t ret = sgx_seal_data(plain_text_length, plain_text, sizeof(data_to_seal), (uint8_t *)&data_to_seal, sealed_len, (sgx_sealed_data_t *)temp_sealed_buf);
    if(ret != SGX_SUCCESS)
    {
        //sgx_thread_mutex_unlock(&g_mutex);
        printf("Failed to seal data\n");
        if (ret == SGX_ERROR_INVALID_PARAMETER) 
        {
	   printf("ENCLAVE: SGX_ERROR_INVALID_PARAMETER\n");

	//return;
        }
        if (ret == SGX_ERROR_INVALID_CPUSVN)
        {

	   printf("ENCLAVE: SGX_ERROR_INVALID_CPUSVN\n");
	  //return;

        }
        if (ret == SGX_ERROR_INVALID_ISVSVN) 
        {
	   printf("ENCLAVE: SGX_ERROR_INVALID_ISVSVN\n");
	   //return;
        }
        if (ret == SGX_ERROR_MAC_MISMATCH)
        {
	   printf("ENCLAVE: SGX_ERROR_MAC_MISMATCH\n");
	   //return;
        }

        if (ret == SGX_ERROR_OUT_OF_MEMORY)
        {
	   printf("ENCLAVE: SGX_ERROR_OUT_OF_MEMORY\n");
	   //return;
        }

        if (ret == SGX_ERROR_UNEXPECTED) 
        {
	   printf("ENCLAVE: SGX_ERROR_UNEXPECTED\n");
	   //return;
        }
        free_allocated_memory(temp_sealed_buf);
        return;
    }
    
    memcpy(output, temp_sealed_buf, sealed_len);
    
}

void unseal_vcf_string(uint8_t* blob, int* unsealed_length, int length)
{
    uint8_t *plain_text = NULL;
    uint32_t plain_text_length = 0;
    
    
    uint8_t* blob_in_enc= (uint8_t*)malloc(length);
    memcpy(blob_in_enc, blob, length);
    printf("length of decrypted text buffer %d \n",sgx_get_encrypt_txt_len((sgx_sealed_data_t *)blob_in_enc));
    uint32_t decrypted_text_len = sgx_get_encrypt_txt_len((sgx_sealed_data_t *)blob_in_enc);
    if(decrypted_text_len == UINT32_MAX)
    {
       printf("AAAAAAAAAAAAAAAAAAAAAAdecrypted text length failure \n");
    }
    uint32_t* unsealed_data = 0;//(uint32_t *)malloc(20000);//(uint32_t *)malloc(sgx_get_encrypt_txt_len((sgx_sealed_data_t *)blob_in_enc)); 
    uint32_t unsealed_data_length = unsealed_length[0];////unsealed_length[0];

    //printf("sealed blob length %d \n",strlen(blob));
    printf("unsealed data length %d \n",unsealed_data_length);
    printf("length %d \n", length);
    
    sgx_status_t ret = sgx_unseal_data((sgx_sealed_data_t *)blob_in_enc, plain_text, &plain_text_length, (uint8_t *)&unsealed_data, &unsealed_data_length);

   if (ret == SGX_ERROR_INVALID_PARAMETER) 
   {
	printf("ENCLAVE: SGX_ERROR_INVALID_PARAMETER\n");

	//return;
   }
   if (ret == SGX_ERROR_INVALID_CPUSVN)
   {

	printf("ENCLAVE: SGX_ERROR_INVALID_CPUSVN\n");
	//return;

   }
   if (ret == SGX_ERROR_INVALID_ISVSVN) 
   {
	printf("ENCLAVE: SGX_ERROR_INVALID_ISVSVN\n");
	//return;
   }
   if (ret == SGX_ERROR_MAC_MISMATCH)
   {
	printf("ENCLAVE: SGX_ERROR_MAC_MISMATCH\n");
	//return;
   }

   if (ret == SGX_ERROR_OUT_OF_MEMORY)
   {
	printf("ENCLAVE: SGX_ERROR_OUT_OF_MEMORY\n");
	//return;
   }

   if (ret == SGX_ERROR_UNEXPECTED) 
   {
	printf("ENCLAVE: SGX_ERROR_UNEXPECTED\n");
	//return;
   }
   
    //uint32_t* unsealed_data_copy = (uint32_t *)malloc(3000000);
    //memcpy(unsealed_data_copy, unsealed_data, 3000000);
    printf("HERE \n");
    printf("LOADED UNSEALED DAta  %s \n", (char*)unsealed_data);
    printf("\n \n \n ");
    printf("length of LOADED unsealed data %d \n", strlen((char*)unsealed_data));
    printf("length of loaded unsealed data %d %d \n", strlen((char*)unsealed_data), unsealed_data_length);

   //COMMENT: uint32_t* unsealed_data contains the unsealed data
    char* ch;
    std::string container;
    int track = 0;
    ch = strtok((char*)unsealed_data, ",");
    while (ch != NULL) 
    {
      std::string container = std::string(ch);
      int last_pos = container.find_last_of("-");
      std::string key = container.substr(0, last_pos);
      int cnt = atoi(container.substr(last_pos + 1).c_str());
      dsnpcase[key] += cnt;
      lsnp.insert(key);
  
      if(key == "1")
      {
         printf("for case 1 last_pos %d \n", last_pos); 
         printf("%s \n", ch);
         printf("track %d \n", track);
      }
      ch = strtok(NULL, ",");
      container.clear();
    } 
    
}


void unseal_vcf_string_control(uint8_t* blob, int* unsealed_length, int length)
{
    uint8_t *plain_text = NULL;
    uint32_t plain_text_length = 0;
    
    
    uint8_t* blob_in_enc= (uint8_t*)malloc(length);
    memcpy(blob_in_enc, blob, length);
    printf("length of decrypted text buffer %d \n",sgx_get_encrypt_txt_len((sgx_sealed_data_t *)blob_in_enc));
    uint32_t decrypted_text_len = sgx_get_encrypt_txt_len((sgx_sealed_data_t *)blob_in_enc);
    if(decrypted_text_len == UINT32_MAX)
    {
       printf("AAAAAAAAAAAAAAAAAAAAAAdecrypted text length failure \n");
    }
    uint32_t* unsealed_data = 0;//(uint32_t *)malloc(20000);//(uint32_t *)malloc(sgx_get_encrypt_txt_len((sgx_sealed_data_t *)blob_in_enc)); 
    uint32_t unsealed_data_length = unsealed_length[0];////unsealed_length[0];

    //printf("sealed blob length %d \n",strlen(blob));
    printf("unsealed data length %d \n",unsealed_data_length);
    printf("length %d \n", length);
    
    sgx_status_t ret = sgx_unseal_data((sgx_sealed_data_t *)blob_in_enc, plain_text, &plain_text_length, (uint8_t *)&unsealed_data, &unsealed_data_length);

   if (ret == SGX_ERROR_INVALID_PARAMETER) 
   {
	printf("ENCLAVE: SGX_ERROR_INVALID_PARAMETER\n");

	//return;
   }
   if (ret == SGX_ERROR_INVALID_CPUSVN)
   {

	printf("ENCLAVE: SGX_ERROR_INVALID_CPUSVN\n");
	//return;

   }
   if (ret == SGX_ERROR_INVALID_ISVSVN) 
   {
	printf("ENCLAVE: SGX_ERROR_INVALID_ISVSVN\n");
	//return;
   }
   if (ret == SGX_ERROR_MAC_MISMATCH)
   {
	printf("ENCLAVE: SGX_ERROR_MAC_MISMATCH\n");
	//return;
   }

   if (ret == SGX_ERROR_OUT_OF_MEMORY)
   {
	printf("ENCLAVE: SGX_ERROR_OUT_OF_MEMORY\n");
	//return;
   }

   if (ret == SGX_ERROR_UNEXPECTED) 
   {
	printf("ENCLAVE: SGX_ERROR_UNEXPECTED\n");
	//return;
   }
   
    //uint32_t* unsealed_data_copy = (uint32_t *)malloc(3000000);
    //memcpy(unsealed_data_copy, unsealed_data, 3000000);
    printf("HERE \n");
    printf("LOADED UNSEALED DAta  %s \n", (char*)unsealed_data);
    printf("\n \n \n ");
    printf("length of LOADED unsealed data %d \n", strlen((char*)unsealed_data));
    printf("length of loaded unsealed data %d %d \n", strlen((char*)unsealed_data), unsealed_data_length);

   //COMMENT: uint32_t* unsealed_data contains the unsealed data
    char* ch;
    std::string container;
    int track = 0;
    ch = strtok((char*)unsealed_data, ",");
    while (ch != NULL) 
    {
      std::string container = std::string(ch);
      int last_pos = container.find_last_of("-");
      std::string key = container.substr(0, last_pos);
      int cnt = atoi(container.substr(last_pos + 1).c_str());
      dsnpcontrol[key] += cnt;
      lsnp.insert(key);
  
      if(key == "1")
      {
         printf("for case 1 last_pos %d \n", last_pos); 
         printf("%s \n", ch);
         printf("track %d \n", track);
      }
      ch = strtok(NULL, ",");
      container.clear();
    } 
    
}

*/
