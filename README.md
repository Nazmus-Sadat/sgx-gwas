# sgx-gwas

#Software Guard Extension (SGX) based whole genome variants search

Intel SGX SDK and platform software should be installed before running this applcation.
1. Running the application: 
   At first, cd to the solution directory and use the following command (example is shown below).
   Parameters: Path for case & control data, and the value of K (to generate top K most significant SNPs).
   Example:
   ./app /home/user/genome_data/case/ /home/user/genome_data/control/ 10

2. Pre-proceesing and encrypting the input data:
   In the first run of the application, the input data files are pre-processed and encrypted individually by the application. The encrypted files are stored in the "encrypted_data/case" and "encrypted_data/control" directory. This pre-processing and encryption process is one time. Pre-processing and encryption time is evaluated separately from the computation time. From the second run, the application checks if input data is already pre-processed and encrypted. If so, it does not repeat this process. The application then sends the encrypted data to the enclave. Then, inside enclave, data is decrypted and required computations are performed on plaintext.
   Before running the application for a different dataset, the contents of "encrypted_data/case" and "encrypted_data/control" directory should be deleted.
   Please note that computation time also includes the time for writing output.

3. Output: Two output files will be generated: 1k_chr1_outData_vcfAF.vcf contains allele frequencies of all SNPs treating control and case groups as a whole dataset; 1k_chr1_outData_vcfChisq.vcf provides top K significant SNPs along with p-value of Chi-squared association test.
In the output files, the attributes of a single record are delimitted by "-", and the "rs" prefix of SNP ID is omitted.

#Building the project (if necessary) in hardware mode:
make
