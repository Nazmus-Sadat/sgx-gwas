
#include <string>
#include <assert.h>
#include <sstream>
#include <vector>
#include <fstream>
#include <iostream>
#include <iterator>
#include <dirent.h>
#include <algorithm>
#include <map>
#include <set>
#include <vector>
#include <math.h>
#include <time.h>
#include "Enclave_u.h"
#include "sgx_urts.h"
#include "sgx_tseal.h"
#include "Rijndael.h"
#include "ErrorSupport.h"

#define ENCLAVE_NAME "libenclave.signed.so"
#define TOKEN_NAME "Enclave.token"

#define THREAD_NUM 3
#define Z_EPSILON 0.000001       /* accuracy of critz approximation */
#define Z_MAX 6.0            /* maximum meaningful z value */

#define        LOG_SQRT_PI     0.5723649429247000870717135 /* log (sqrt (pi)) */
#define        I_SQRT_PI       0.5641895835477562869480795 /* 1 / sqrt (pi) */
#define        BIGX           20.0         /* max value to represent exp (x) */
#define        ex(x)             (((x) < -BIGX) ? 0.0 : exp (x))


// Global data
sgx_enclave_id_t global_eid = 0;
sgx_launch_token_t token = {0};

struct buf_t buf;
std::string path = "";
CRijndael oRijndael;
using namespace std;

vector<std::string> af_records;
// Ocall function
void print(const char *str)
{
    cout<<str;
}
/* OCall functions */
void ocall_print_string(const char *str)
{
    /* Proxy/Bridge will check the length and null-terminate 
     * the input string to prevent buffer overflow. 
     */
    printf("%s", str);
}

void insert_af_record(const char* record_str)
{
    std::string record_to_insert = std::string(record_str);
    af_records.push_back(record_to_insert);
    
}

void dump_af_records_to_file()
{
    vector<std::string>::iterator It; 

    std::ofstream af("1k_chr1_outData_vcfAF.vcf");
    if(af.is_open())
    {
       af << "Allele frequencies of SNPs from two groups \n";
       af << "CHROM POS ID REF ALT alleleFreq \n";
       for(It = af_records.begin(); It != af_records.end(); It++)
       { 
           af << (*It);
           af << "\n";
       }
    }
    else
    {
       printf("could not open AF.vcf file to write \n");
       return;
    }
    af.close();

}

void output_af(char *str, int length)
{
    //cout<< "inside ocall for af file write. length is " << length << endl;
    char* af_string;
    af_string = (char*)malloc(length + 1);
    strcpy(af_string, str);
    std::ofstream af("1k_chr1_outData_vcfAF.vcf");
    if(af.is_open())
    {
       af << "Allele frequencies of SNPs from two groups \n";
       af << "CHROM POS ID REF ALT alleleFreq \n";
       af << str;
    }
    else
    {
       printf("could not open AF.vcf file to write \n");
       return;
    }
    af.close();
   
    free(af_string);
}

void output_chis(char *str, int length)
{
    //cout<< "inside ocall for chis file write. length is " << length << endl;
    char* chis_string;
    chis_string = (char*)malloc(length + 1);
    strcpy(chis_string, str);
    std::ofstream chisq("1k_chr1_outData_vcfChisq.vcf");
    if(chisq.is_open())
    {
       chisq << "top K significant SNPs sorted \n";
       chisq << "CHROM POS ID REF ALT p-value \n";
       chisq << chis_string;
    }
    else
    {
       printf("could not open chisq.vcf file to write \n");
       return;
    }
    
    chisq.close();
   
    free(chis_string); 
    
}

void dump_cipher(char* path, char *data, int length)
{
    //cout<< "inside ocall for chis file write. length is " << length << endl;
    char* cipher_string;
    cipher_string = (char*)malloc(length + 1);
    strcpy(cipher_string, data);
    std::ofstream cipherfp(path);
    if(cipherfp.is_open())
    {
       cipherfp << cipher_string;
    }
    else
    {
       printf("could not open cipher file to write \n");
       return;
    }
    
    cipherfp.close();
   
    free(cipher_string); 
    
}

int write_file(char* path, char *data, int length) 
{

    FILE *file = fopen(path, "w");
    int ret = fwrite(data, sizeof(char), length, file);
    if (ret != length)
    {
        printf("write_file: Error %d\n", ret);

    }
    fclose(file);
    return 0;

}

long int load_file(char* path, char *buf)
{

   long int length;
   FILE * f = fopen (path, "rb"); //was "rb"

   if (!f)
   {
      return 1;

   }
   fseek (f, 0, SEEK_END);
   length = ftell (f);
   fseek (f, 0, SEEK_SET);
 
   char *buffer = new char[length]();
   fread (buffer, sizeof(char), length, f);
   fclose (f);

   memcpy(buf, buffer, length);

   return length;
}
// load_and_initialize_enclave():
//		To load and initialize the enclave     
sgx_status_t load_and_initialize_enclave(sgx_enclave_id_t *eid)
{
    sgx_status_t ret = SGX_SUCCESS;
    int retval = 0;
    int updated = 0;

    for( ; ; )
    {
        // Step 1: check whether the loading and initialization operations are caused by power transition.
        //		If the loading and initialization operations are caused by power transition, we need to call sgx_destory_enclave() first.
        if(*eid != 0)
        {
            sgx_destroy_enclave(*eid);
        }
	
        // Step 2: load the enclave
        // Debug: set the 2nd parameter to 1 which indicates the enclave are launched in debug mode
        ret = sgx_create_enclave(ENCLAVE_NAME, SGX_DEBUG_FLAG, &token, &updated, eid, NULL);
        //if(ret != SGX_SUCCESS)
           // return ret;

        // Save the launch token if updated
        if(updated == 1)
        {
            ofstream ofs(TOKEN_NAME, std::ios::binary|std::ios::out);
            if(!ofs.good())
            {
                cout<< "Warning: Failed to save the launch token to \"" <<TOKEN_NAME <<"\""<<endl;
            }
            else
                ofs << token;
        }
     
        if(ret == SGX_SUCCESS)
          return ret;
        else
          continue;
    }
    return ret;
}


bool set_global_data()
{
   
    ifstream ifs(TOKEN_NAME, std::ios::binary | std::ios::in);
    if(!ifs.good())
    {
        memset(token, 0, sizeof(sgx_launch_token_t));
    }
    else
    {
        ifs.read(reinterpret_cast<char *>(&token), sizeof(sgx_launch_token_t));
        if(ifs.fail())
        {
            memset(&token, 0, sizeof(sgx_launch_token_t));
        }
    }

    return true;
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

//Function to convert string of unsigned chars to string of chars
void CharStr2HexStr(unsigned char const* pucCharStr, char* pszHexStr, int iSize)
{
	int i;
	char szHex[3];
	pszHexStr[0] = 0;
	for(i=0; i<iSize; i++)
	{
		Char2Hex(pucCharStr[i], szHex);
		strcat(pszHexStr, szHex);
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

void pre_process_case_data(std::string pathstr)
{
     // Process case
    std::string dirToOpen = pathstr;
    auto dir = opendir(dirToOpen.c_str());

    //std::cout << "Process directory: " << dirToOpen.c_str() << std::endl;

    if(NULL == dir)
    {
        //std::cout << "could not open directory: " << dirToOpen.c_str() << std::endl;
        
    }

    auto entity = readdir(dir);
    int NGroupcase = 0;
    int cnt = 0;
    std::string case_string = "";

    //CRijndael oRijndael;
    //oRijndael.MakeKey("1234567890123456", "1111111122222222", 16, 16);
    //int enc_length = 64;
    
    char* case_result = new char[2];
    
    while(entity != NULL)
    {   //break;

        if(entity->d_type == DT_REG)
        { //regular file
          //cout << dirToOpen + std::string(entity->d_name) << endl;
          std::ifstream in1 (dirToOpen + std::string(entity->d_name));


          string linebuffer1;
    
          if(in1.is_open())
          {
             //cout << "opened" << endl;
             int records_to_discard1 = 2;
             int discard_count1 = 0;
             NGroupcase += 1;
             string encrypted_string = "";
             printf(".");
       
             while(in1 && getline(in1, linebuffer1))
             {
                discard_count1++;
                if(discard_count1 <= records_to_discard1)
                   continue;  
                 //cout<< linebuffer << endl;
                std::istringstream iss(linebuffer1);
                std::vector<std::string> results1((std::istream_iterator<std::string>(iss)),
                                             std::istream_iterator<std::string>());
               


                case_string.append(results1.at(0));
                case_string.append("-");
                case_string.append(results1.at(1));
                case_string.append("-");
                case_string.append(results1.at(2).substr(2));
                case_string.append("-");
                case_string.append(results1.at(3));
                case_string.append("-");
                case_string.append(results1.at(4));
                case_string.append("-");
                (results1.at(7) == "heterozygous")? case_string.append("1"):case_string.append("2");

                int blk_length = 16;
                if(strlen(case_string.c_str()) > 16)
                  blk_length = 32;
                else if(strlen(case_string.c_str()) > 32)
                  blk_length = 48;
                else if(strlen(case_string.c_str()) > 48)
                  blk_length = 64;
                else
                  blk_length = 80;

                char case_string_char[blk_length + 1];
                char case_string_to_encrypt[blk_length + 1];
                char case_string_encrypted[blk_length + 1];
                char hex_container[blk_length + 1];
               
                memset(case_string_char, 0, blk_length + 1);
                memset(case_string_to_encrypt, 0, blk_length + 1);
                memset(case_string_encrypted, 0, blk_length + 1);
                memset(hex_container, 0, blk_length + 1);

                oRijndael.ResetChain();
                //strcpy(case_string_char, case_string.c_str());
                strcpy(case_string_to_encrypt, case_string.c_str());
                memset(case_string_encrypted, 0, blk_length + 1);
                oRijndael.Encrypt(case_string_to_encrypt, case_string_encrypted, blk_length, CRijndael::CBC);
                CharStr2HexStr((unsigned char const*)case_string_encrypted, hex_container, blk_length);
                //cout << "encrypted case string portion " << hex_container << endl;

                encrypted_string.append(hex_container).append(",");
          
               
                //cout<< "Decrypted case string portion  " << decrypted_case_string <<endl;

                //case_string.append(",");
                case_string = "";
           
                
            }
            //process_case_data(global_eid, (char*)encrypted_string.c_str(), strlen(encrypted_string.c_str())+1);
            dump_cipher((char*)(std::string("encrypted_data/case/") + std::string(entity->d_name)).c_str(), (char*)encrypted_string.c_str(), strlen(encrypted_string.c_str()));
       
          } 
          else
          {
                cout << "could not open file" << endl;
          }
          
        }
        entity = readdir(dir);
    }
    printf("\n");
    return;

}

void pre_process_control_data(std::string pathstr)
{
     // preprocess control
    std::string dirToOpen = pathstr;
    auto dir = opendir(dirToOpen.c_str());

    //std::cout << "Process directory: " << dirToOpen.c_str() << std::endl;

    if(NULL == dir)
    {
        std::cout << "could not open directory: " << dirToOpen.c_str() << std::endl;
        
    }

    auto entity = readdir(dir);
    int NGroupcontrol = 0;
    //std::map<std::string, int> dsnpcontrol;
    int cnt = 0;
    std::string control_string = "";
  
    while(entity != NULL)
    {  
        
        if(entity->d_type == DT_REG)
        { //regular file
          //cout << dirToOpen + std::string(entity->d_name) << endl;
          std::ifstream in1 (dirToOpen + std::string(entity->d_name));


          string linebuffer1;
    
          if(in1.is_open())
          {
             //cout << "opened" << endl;
             int records_to_discard1 = 2;
             int discard_count1 = 0;
             NGroupcontrol += 1;
             string encrypted_string = "";
             printf(".");
       
             while(in1 && getline(in1, linebuffer1))
             {
                discard_count1++;
                if(discard_count1 <= records_to_discard1)
                   continue;  
                 //cout<< linebuffer << endl;
                std::istringstream iss(linebuffer1);
                std::vector<std::string> results1((std::istream_iterator<std::string>(iss)),
                                             std::istream_iterator<std::string>());
                
                
                control_string.append(results1.at(0));
                control_string.append("-");
                control_string.append(results1.at(1));
                control_string.append("-");
                control_string.append(results1.at(2).substr(2));
                control_string.append("-");
                control_string.append(results1.at(3));
                control_string.append("-");
                control_string.append(results1.at(4));
                control_string.append("-");
                (results1.at(7) == "heterozygous")? control_string.append("1"):control_string.append("2");
                 
                int blk_length = 16;
                if(strlen(control_string.c_str()) > 16)
                  blk_length = 32;
                else if(strlen(control_string.c_str()) > 32)
                  blk_length = 48;
                else if(strlen(control_string.c_str()) > 48)
                  blk_length = 64;
                else
                  blk_length = 80;

                char control_string_char[blk_length + 1];//char* case_string_char = (char*)malloc(strlen(case_string.c_str()) + 1);
               
                char control_string_to_encrypt[blk_length + 1];//char* case_string_to_encrypt = (char*)malloc(strlen(case_string.c_str()) + 1);
                char control_string_encrypted[blk_length + 1];//char* case_string_encrypted = (char*)malloc(strlen(case_string.c_str()) + 1);
                char hex_container[blk_length + 1];//char* hex_container = (char*)malloc(strlen(case_string.c_str()) + 1);
                // char temp[17];
                memset(control_string_char, 0, blk_length + 1);
                memset(control_string_to_encrypt, 0, blk_length + 1);
                memset(control_string_encrypted, 0, blk_length + 1);
                memset(hex_container, 0, blk_length + 1);

                //Test CBC
                oRijndael.ResetChain();
                //strcpy(control_string_char, control_string.c_str());
                strcpy(control_string_to_encrypt, control_string.c_str());
                memset(control_string_encrypted, 0, blk_length + 1);
                oRijndael.Encrypt(control_string_to_encrypt, control_string_encrypted, blk_length, CRijndael::CBC);
                CharStr2HexStr((unsigned char const*)control_string_encrypted, hex_container, blk_length);
                //cout << "encrypted control string portion " << hex_container << endl;

                encrypted_string.append(hex_container).append(",");
                
                control_string = "";
    
            }
             //process_control_data(global_eid, (char*)encrypted_string.c_str(), strlen(encrypted_string.c_str())+1);
             dump_cipher((char*)(std::string("encrypted_data/control/") + std::string(entity->d_name)).c_str(), (char*)encrypted_string.c_str(), strlen(encrypted_string.c_str()));
           
          } 
          else
          {
                cout << "could not open file" << endl;
          }
          
        }
        entity = readdir(dir);
    }
    printf("\n");
    return; 

}

int main(int argc, char* argv[])
{
    (void)argc, (void)argv;


    // Initialize the global data
    if(!set_global_data())
    {
        //release_source();
        //cout << "Enter a character before exit ..." << endl;
        //getchar();
        return -1;
    }

    // Load and initialize the signed enclave
    // sealed_buf == NULL indicates it is the first time to initialize the enclave.
    sgx_status_t ret = load_and_initialize_enclave(&global_eid);
    if(ret != SGX_SUCCESS)
    {
        ret_error_support(ret);
        //release_source();
        //cout << "Enter a character before exit ..." << endl;
        //getchar();
        return -1;
    }
    cout << "Initialization complete" << endl;

    if(argc < 4)  
    {
	cout<<"Insufficient arguments,... exiting" << endl; 
	return 0;
    }

     //Measure pre-processing time
    const clock_t begin_preprocessing_time = clock(); 

    char* case_path = (char*)malloc(strlen(argv[1]) + 1);
    strcpy(case_path, argv[1]);
   
    char* control_path = (char*)malloc(strlen(argv[2]) + 1);
    strcpy(control_path, argv[2]);

    int K = atoi(argv[3]);

    std::string dir_to_open_for_check = "encrypted_data/case/";
    auto dir_check = opendir(dir_to_open_for_check.c_str());
    auto entity_check = readdir(dir_check);

    bool data_preprocessed = false;
    while(entity_check != NULL)
    {
        if(entity_check->d_type == DT_REG)
        { //regular file
          
           data_preprocessed = true;
           cout << "Data was pre-processed before " << endl;
           break;
        }
        entity_check = readdir(dir_check);
    }

    oRijndael.MakeKey("1234567890123456", "1111111122222222", 16, 16);
    if(!data_preprocessed)
       pre_process_case_data(std::string(case_path));
    
    if(!data_preprocessed)
       pre_process_control_data(std::string(control_path)); //"/home/sadat/mydrive/SGX/data002/control/"

     //Measure pre-processing time
    const clock_t end_preprocessing_time = clock();
    float preprocessing_time = float(end_preprocessing_time - begin_preprocessing_time ) /  CLOCKS_PER_SEC;
    if(!data_preprocessed)
      std::cout << "Pre-processing time is " << preprocessing_time << " seconds" << endl;

    string linebuffer;

    //Measure computation time
    const clock_t begin_computation_time = clock();

    
    // Process case
    std::string dirToOpen = "encrypted_data/case/";
    auto dir = opendir(dirToOpen.c_str());

    //set the new path for the content of the directory
    path = dirToOpen + "/";

    //std::cout << "Process directory: " << dirToOpen.c_str() << std::endl;

    if(NULL == dir)
    {
        std::cout << "could not open directory: " << dirToOpen.c_str() << std::endl;
        
    }

    auto entity = readdir(dir);
    int NGroupcase = 0;
    //std::map<std::string, int> dsnpcase;
    //int cnt = 0;
    std::string case_string = "";

    //CRijndael oRijndael;
    
    char* case_result = new char[2];
    
    while(entity != NULL)
    {   //break;
        if(entity->d_type == DT_REG)
        { //regular file
          //cout << dirToOpen + std::string(entity->d_name) << endl;
          std::ifstream in1 (dirToOpen + std::string(entity->d_name));


          string linebuffer1;
    
          if(in1.is_open())
          {
             //cout << "opened" << endl;
             //int records_to_discard1 = 2;
             //int discard_count1 = 0;
             NGroupcase += 1;
             //string encrypted_string = "";
             printf(".");
       
             while(in1 && getline(in1, linebuffer1))
             {
                process_case_data(global_eid, (char*)linebuffer1.c_str(), strlen(linebuffer1.c_str())+1); 
             }
       
          } 
          else
          {
                cout << "could not open file" << endl;
          }
          
        }
        entity = readdir(dir);
    }
    printf("\n");
   
    //COMMENT: Process control
    dirToOpen = "encrypted_data/control/";
    dir = opendir(dirToOpen.c_str());

    //set the new path for the content of the directory
    path = dirToOpen + "/";

    //std::cout << "Process directory: " << dirToOpen.c_str() << std::endl;

    if(NULL == dir)
    {
        std::cout << "could not open directory: " << dirToOpen.c_str() << std::endl;
        
    }

    entity = readdir(dir);
    int NGroupcontrol = 0;
    //std::map<std::string, int> dsnpcontrol;
    //cnt = 0;
    //std::string control_string = "";
   
   
    while(entity != NULL)
    {   
        if(entity->d_type == DT_REG)
        { //regular file
          //cout << dirToOpen + std::string(entity->d_name) << endl;
          std::ifstream in1 (dirToOpen + std::string(entity->d_name));


          string linebuffer1;
    
          if(in1.is_open())
          {
            // cout << "opened" << endl;
             //int records_to_discard1 = 2;
             //int discard_count1 = 0;
             NGroupcontrol += 1;
             printf(".");
             //string encrypted_string = "";
       
             while(in1 && getline(in1, linebuffer1))
             {
                 process_control_data(global_eid, (char*)linebuffer1.c_str(), strlen(linebuffer1.c_str())+1);
             }
          } 
          else
          {
                cout << "could not open file" << endl;
          }
          
        }
        entity = readdir(dir);
    }
    printf("\n");

    populateGroupSize(global_eid, &NGroupcase, &NGroupcontrol, &K); 

    int* lengths = new int[2];
    // chi_length = 0;
    //int af_length = 0;
    compute(global_eid, lengths, sizeof(lengths));
    
    int chi_length = lengths[0];
    int af_length = lengths[1];

    //cout<< "in app" << chi_length << " " << af_length << endl;

    char* chi_str_param = (char*)malloc(chi_length + 1);
    char* af_str_param = (char*)malloc(af_length + 1);
  
    //const clock_t begin_output_time = clock();
    
    writeOutput(global_eid, chi_str_param, af_str_param, chi_length, af_length);
    
    //printf("chi str %d %s \n", strlen(chi_str_param), chi_str_param);
    
    output_chis(chi_str_param, strlen(chi_str_param)); 
    free(chi_str_param);

    dump_af_records_to_file();
    //output_af(af_str_param, strlen(af_str_param));
    free(af_str_param);

    //cout << case_string << endl;
    closedir(dir);

    //Measure computation time
    const clock_t end_computation_time = clock();
    float computation_time = float(end_computation_time - begin_computation_time ) /  CLOCKS_PER_SEC;
    std::cout << "Computation time is " << computation_time << " seconds" <<endl;

    //free(input_vcf_char);
    // Release resources
    //release_source();
    
    // Destroy the enclave
    sgx_destroy_enclave(global_eid);

    //cout << "Enter a character before exit ..." << endl;
    //getchar();
    return 0;
}

