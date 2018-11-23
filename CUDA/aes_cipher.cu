#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <cuda_runtime.h>
#include "my_utils.h" // Contains the precomputed matrices used for the AES algorithm

#define byte unsigned char
#define THREADS 256 // Need to compute this correctly
#define THREAD_BLOCKS 32 // Need to compute this correctly


/*************************************** CPU ********************************************/
/****************************** Auxiliary functions *************************************/

// To read a file containing the key used to cipher
void read_key_from_file(byte *key) {
   FILE *fp;
   byte *key_file = (byte*)"key.txt";
   byte buffer[20];
   byte i;

   if((fp = fopen((const char*)key_file, "rb")) == NULL){
       printf(" Cannot open input file: %s\n",key_file);
       printf(" Exiting program...\n");
       return;
   }

   fgets((char*)buffer, 16, (FILE*)fp);
   for(i = 0;i < 16;i++) {
      key[i]=buffer[i];
   }                                                                                                                
   fclose(fp);
   printf("Key stored correctly.\n");
}

// To measure the size of a file
unsigned long get_file_size(FILE *f){
    int prev = ftell(f);
    fseek(f, 0L, SEEK_END);
    int size = ftell(f);
    fseek(f, prev, SEEK_SET);
    return size;
}

// To read a file from the PC and to copy the binary data to an array of bytes
// returns the size of the file or -1 if there was an error
long long load_file(byte *file_in_name, byte **file_in) {
    FILE *f_i; // Pointer to the file
    unsigned long size; // Size of the file

    // Open file
    if((f_i = fopen((const char*)file_in_name,"rb")) == NULL)  {
        printf("Error trying to open the file %s\n", file_in_name);
        return -1;
    }          
    // Compute size of the file          
    size = get_file_size(f_i);

    // Allocate memory to store the input file as binary data
    *file_in = (byte*)malloc(size * sizeof(byte));
    // Read all the data from the file and save it in the array
    fread(*file_in, sizeof(byte), size, f_i);

    // Close file (no longer required)
    fclose(f_i);

    return size;
}

// To write the buffer of data to a file in the PC
void write_file(byte *file_out_name, byte *file_out, long long *file_out_size) {
    FILE *f_o; // Pointer to the file

    // Open file
    if((f_o = fopen((const char*)file_out_name,"wb")) == NULL)  {
        printf("Error trying to open the file %s\n", file_out_name);
        return;
    }

    fwrite(file_out, sizeof(byte), *file_out_size, f_o);

    fclose(f_o);
}


/*************************************** GPU *****************************************************/
/*************************************** Auxiliary functions *************************************/

// Print the data contained in the state
__device__ void print_state(byte *state) {
   for(int i = 0; i < 4; i++) {
      for (int j = 0; j < 4; j++) {
         printf("%0X ", state[i*4+j]);
      }
      printf("\n");
   }
}

// Get the data from the auxiliary matrices
__device__ byte get_sbox(byte pos, byte *d_sbox)  { return d_sbox[pos];}
__device__ byte mul_2(byte a, byte *d_m2)       { return d_m2[a]; }
__device__ byte mul_3(byte a, byte *d_m3)       { return d_m3[a]; }

// Circular shift to the left by one position
__device__ void rotateLeft(byte *A) {    
    byte i;
    byte aux = A[0];    
    for(i=0;i<3;i++) {
        A[i] = A[i+1];
    }
    A[3] = aux;
}
/*************************************** AES functions *************************************/
// To expand the key using the SBOX matrix
__global__ void key_expansion(byte *key, byte *expanded_key, byte *d_sbox, byte *d_rcon) {
    byte temp[4];
    byte c=16;
    byte j, a, i=1;
    for(j=0; j < 16; j++) {
        expanded_key[j] = key[j];
    }
    while(c < 176) {
        for(a = 0; a < 4; a++) {
            temp[a] = expanded_key[a+c-4];
        }
        if(c % 16 == 0) {
            rotateLeft(temp);
            for(a = 0; a < 4; a++) {
                temp[a] = get_sbox(temp[a],d_sbox);
            }
            temp[0] =  temp[0] ^ d_rcon[i];
            i++;
        }
        for(a = 0; a < 4; a++) {
            expanded_key[c] = expanded_key[c-16] ^ temp[a];
            c++;
        }
    }
}

// To merge the expanded key with the data of the state
__device__ void add_round_key(byte *state, int round, byte *expanded_key) {
    // The data block used in the expanded key depends on the number of round
    int i, j;
    for(i=0;i<4;i++) {
        for(j=0;j<4;j++) {
            state[i * 4 + j] ^= expanded_key[round*16 + i*4 + j];
        }        
    }
}

// To substitute the value of the state with the corresponding value in the SBOX matrix
__device__ void subbytes(byte *state, byte *d_sbox) {
    byte i, j;
    for(i=0;i<4;i++) 
        for(j=0;j<4;j++) 
            state[j * 4 + i] = get_sbox(state[j * 4 + i], d_sbox);
}

// To change the order in each row performing shifts to the left
__device__ void shift_rows(byte *state) {    
    byte temp[4];// = (byte*)malloc(4);

    memcpy(temp, state + 4, 4);
    rotateLeft(temp);        
    memcpy(state + 4, temp, 4);

    memcpy(temp, state + 8, 4);
    rotateLeft(temp);
    rotateLeft(temp);
    memcpy(state + 8, temp, 4);

    memcpy(temp, state + 12, 4);
    rotateLeft(temp);
    rotateLeft(temp);
    rotateLeft(temp);
    memcpy(state + 12, temp, 4);
}



// To perform a substitution that uses finite fields arithmetic over GF(2^^8).
__device__ void mix_columns(byte *state, byte *d_m2, byte *d_m3) {
    byte i, a0, a1, a2, a3;
    for(i=0;i<4;i++) {
        a0 = state[i * 4 + 0];
        a1 = state[i * 4 + 1];
        a2 = state[i * 4 + 2];
        a3 = state[i * 4 + 3];

        state[i * 4 + 0] = mul_2(a0, d_m2) ^ mul_3(a1, d_m3) ^ a2 ^ a3;
        state[i * 4 + 1] = mul_2(a1, d_m2) ^ mul_3(a2, d_m3) ^ a0 ^ a3;
        state[i * 4 + 2] = mul_2(a2, d_m2) ^ mul_3(a3, d_m3) ^ a0 ^ a1;
        state[i * 4 + 3] = mul_2(a3, d_m2) ^ mul_3(a0, d_m3) ^ a1 ^ a2;        
    }
}

// To cipher the block of data using the AES algorithm
__device__ void cipher(byte *state, byte *expanded_key, byte *d_sbox, byte *d_m2, byte* d_m3) {    
    int round=0;    
    add_round_key(state, round, expanded_key);    
    for(round=1; round < 10 ; round++) {
        subbytes(state, d_sbox);
        shift_rows(state);
        mix_columns(state, d_m2, d_m3);
        add_round_key(state, round, expanded_key);
    }
    subbytes(state, d_sbox);
    shift_rows(state);
    add_round_key(state, 10, expanded_key);    
}


__global__ void cipher_control(byte *file_in, byte *file_out, long long *file_size, 
                    unsigned long *blocks, byte *expanded_key, byte *d_sbox, byte *d_m2, byte *d_m3)
{
    byte state[16];
    int block;
    int padding, res;

    block = blockIdx.x * blockDim.x + threadIdx.x;

    // Check if the size of the input file is multiple of 16
    res = *file_size % 16;

    while(block < *blocks) {
        // Copy the block of memory from the input file to the state
        memcpy(state, file_in + block  * 16, 16 * sizeof(byte));
        
        // Check if it is necessary to add padding to the last block
        if(block == ((*blocks) - 1) && res != 0) {
            padding = 16 - res;
            // Remember to change this in order to write to the correct memory
            for(int i = res;i < res + padding;i++) {
                state[i] = 0x00;
            }
        }

        // Invoke the cipher process for the corresponding block
        cipher(state, expanded_key, d_sbox, d_m2, d_m3);

        // Copy the encrypted block to the output file
        memcpy(file_out + block  * 16, state, 16 * sizeof(byte));

        block += gridDim.x * blockDim.x;
    }

}





int main(int argc, char *argv[]) {
    if(argc < 3) {
        printf("You must provide the name, route and extension of the file to be encrypted as well as the name for output\n");
        printf("Example: ./encryp files/test.jpg files/test.aes\n");
        return 0;
    }
    // Name of the input and output files
    byte *file_name = (byte*)argv[1];
    byte *out_file_name = (byte*)argv[2];

    // Pointers to data in the HOST memory
    byte *file_in;              // Stores the binary data of the file to be encrypted
    byte *file_out;             // Stores the binary data of the encrypted file
    byte *key;                  // Stores the key provided by the user 
    byte *expanded_key;         // The key after the expansion algorithm
    long long *file_in_size;    // Size of the input file
    long long *file_out_size;   // Size of the output file
    unsigned long *blocks;      // Number of blocks to divide the input file for the AES process
    unsigned long padding;      // Number of bytes of padding
    
    // Pointers to data in the DEVICE memory
    byte *d_file_in;
    byte *d_file_out;
    byte *d_key;
    byte *d_expanded_key;
    long long *d_file_in_size;
    unsigned long *d_blocks;
    byte *d_sbox;
    byte *d_m2;
    byte *d_m3;
    byte *d_rcon;


    int byte_size = sizeof(byte);

    /* ------------ Allocate HOST memory ------------------------------*/
    key =           (byte*)          malloc(16  * byte_size);
    expanded_key =  (byte*)          malloc(176 * byte_size);
    file_in_size =  (long long*)     malloc(sizeof(long long));
    file_out_size = (long long*)     malloc(sizeof(long long));
    blocks =        (unsigned long*) malloc(sizeof(unsigned long));

    printf("AES Cipher using CUDA\n\n");
      
    /* --------  Starting encryption pre-process --------------------*/

    // Load the file to be encrypted
    *file_in_size = load_file(file_name, &file_in);
    if(*file_in_size == -1) {
        printf("Error trying to read the file");
        return 1;
    }
    
    // Compute the number of blocks needed and check whether the file requires
    // padding at the end (when it is not a multiple of 16)
    *blocks = (*file_in_size) / 16;
    padding = 0;
    if(*file_in_size % 16 != 0) {
        padding = 16 - (*file_in_size) % 16;
        (*blocks)++;
    }
    // The size of the output file will be a multiple of 16 + 1 because of the byte at the beginning to indicate the padding
    *file_out_size = (*blocks) * 16 + 1;

    // Allocate the memory for the output file
    file_out = (byte*)malloc((*file_out_size) * byte_size);
    // Write in the first byte of the output the number of padding bytes
    file_out[0] = padding;

    // Read the key used to encrypt
    read_key_from_file(key);
    
    //  -----------------------      Allocate DEVICE memory   -----------------------
    cudaMalloc((void**)&d_file_in,      byte_size * (*file_in_size));
    cudaMalloc((void**)&d_file_out,     byte_size * (*file_out_size));
    cudaMalloc((void**)&d_key,          byte_size *  16);
    cudaMalloc((void**)&d_expanded_key, byte_size * 176);
    cudaMalloc((void**)&d_sbox,         byte_size * 256);
    cudaMalloc((void**)&d_m2,           byte_size * 256);
    cudaMalloc((void**)&d_m3,           byte_size * 256);
    cudaMalloc((void**)&d_rcon,         byte_size *  11);
    cudaMalloc((void**)&d_file_in_size, sizeof(long long));
    cudaMalloc((void**)&d_blocks,       sizeof(unsigned long));

    // GPU memory copy
    cudaMemcpy(d_file_in,      file_in,      byte_size * (*file_in_size),  cudaMemcpyHostToDevice);
    cudaMemcpy(d_key,          key,          byte_size *  16,              cudaMemcpyHostToDevice);
    cudaMemcpy(d_sbox,         SBOX,         byte_size * 256,              cudaMemcpyHostToDevice);
    cudaMemcpy(d_m2,           M2,           byte_size * 256,              cudaMemcpyHostToDevice);
    cudaMemcpy(d_m3,           M3,           byte_size * 256,              cudaMemcpyHostToDevice);
    cudaMemcpy(d_rcon,         RCON,         byte_size *  11,              cudaMemcpyHostToDevice);
    cudaMemcpy(d_file_in_size, file_in_size, sizeof(long long),            cudaMemcpyHostToDevice);
    cudaMemcpy(d_blocks,       blocks,       sizeof(unsigned long),        cudaMemcpyHostToDevice);


    // Expand the key from 16 bytes to 176
    key_expansion <<<1, 1>>>(d_key, d_expanded_key, d_sbox, d_rcon);

    // For synchronization purposes
    cudaMemcpy(expanded_key, d_expanded_key, byte_size * 176,              cudaMemcpyDeviceToHost);


    // Define the grid of threads used
    dim3 Threads(THREADS, THREADS);
    dim3 Thread_Blocks(THREAD_BLOCKS, THREAD_BLOCKS);

    printf("Starting encryption...\n");
    // Measure time
    double time_taken = 0;
    
    for(int i = 0; i < 10; i++) {
        start_timer();
        cipher_control <<< 128, 128>>> (d_file_in, d_file_out + 1, d_file_in_size, d_blocks, d_expanded_key, d_sbox, d_m2, d_m3);
        time_taken += stop_timer();
        cudaDeviceSynchronize();
    }
    printf("Done encryption. Time = %lf ms\n", time_taken/10.0);

    file_out[0] = padding;

    cudaMemcpy(file_out + 1, d_file_out + 1, byte_size * (*file_out_size -1),              cudaMemcpyDeviceToHost);

    printf("Saving the file...\n");
    write_file(out_file_name, file_out, file_out_size);


    free(file_in);
    free(file_out);
    free(file_in_size);
    free(file_out_size);
    free(blocks);
    free(key);
    free(expanded_key);

    cudaFree(d_file_in);
    cudaFree(d_file_out);
    cudaFree(d_file_in_size);
    cudaFree(d_blocks);
    cudaFree(d_key);
    cudaFree(d_expanded_key);
    cudaFree(d_sbox);
    cudaFree(d_rcon);
    cudaFree(d_m2);
    cudaFree(d_m3);

    printf("Finished.\n");
    
    return 0; 
}