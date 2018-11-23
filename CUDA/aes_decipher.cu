#include <stdio.h>
#include <stdlib.h>
#include <string.h>
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
__device__ byte get_rsbox(byte pos, byte *d_rsbox)  { return d_rsbox[pos];}
__device__ byte get_sbox( byte pos, byte *d_sbox)   { return d_sbox[pos];}
__device__ byte mul_9(byte  a, byte *d_m9)          { return d_m9[a];  }
__device__ byte mul_11(byte a, byte *d_m11)         { return d_m11[a]; }
__device__ byte mul_13(byte a, byte *d_m13)         { return d_m13[a]; }
__device__ byte mul_14(byte a, byte *d_m14)         { return d_m14[a]; }

// Circular shift to the left by one position
__device__ void rotateLeft(byte *A) {    
    byte i;
    byte aux = A[0];    
    for(i=0;i<3;i++) {
        A[i] = A[i+1];
    }
    A[3] = aux;
}
// Circular shift to the right by one position
__device__ void rotateRight(byte *A) {        
    byte i;
    byte aux = A[3];    
    for(i=3;i>0;i--) {
        A[i] = A[i-1];
    }
    A[0] = aux;
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
__device__ void inverse_subbytes(byte *state, byte *d_rsbox) {
    byte i, j;
    for(i=0;i<4;i++) 
        for(j=0;j<4;j++) 
            state[j * 4 + i] = get_rsbox(state[j * 4 + i], d_rsbox);
}

// To change the order in each row performing shifts to the right
__device__ void inverse_shift_rows(byte *state) {    
    byte temp[4];

    memcpy(temp, state + 4, 4);
    rotateRight(temp);        
    memcpy(state + 4, temp, 4);

    memcpy(temp, state + 8, 4);
    rotateRight(temp);
    rotateRight(temp);
    memcpy(state + 8, temp, 4);

    memcpy(temp, state + 12, 4);
    rotateRight(temp);
    rotateRight(temp);
    rotateRight(temp);
    memcpy(state + 12, temp, 4);
}



// To perform a substitution that uses finite fields arithmetic over GF(2^^8).
__device__ void inverse_mix_columns(byte *state, byte *d_m9, byte *d_m11, byte *d_m13, byte *d_m14) {
    byte i, a0, a1, a2, a3;
    for(i=0;i<4;i++) {
        a0 = state[i * 4 + 0];
        a1 = state[i * 4 + 1];
        a2 = state[i * 4 + 2];
        a3 = state[i * 4 + 3];

        state[i * 4 + 0] = mul_14(a0, d_m14) ^ mul_11(a1, d_m11) ^ mul_13(a2, d_m13) ^ mul_9( a3, d_m9);
        state[i * 4 + 1] = mul_9( a0, d_m9)  ^ mul_14(a1, d_m14) ^ mul_11(a2, d_m11) ^ mul_13(a3, d_m13);
        state[i * 4 + 2] = mul_13(a0, d_m13) ^ mul_9( a1, d_m9)  ^ mul_14(a2, d_m14) ^ mul_11(a3, d_m11);
        state[i * 4 + 3] = mul_11(a0, d_m11) ^ mul_13(a1, d_m13) ^ mul_9( a2, d_m9)  ^ mul_14(a3, d_m14);
    }
}

// To decipher the block of data using the AES algorithm
__device__ void decipher(byte *state, byte *expanded_key, byte *d_rsbox, byte *d_m9, byte *d_m11, byte *d_m13, byte *d_m14) {    
    int round;
    add_round_key(state, 10, expanded_key);    
    for(round = 9; round > 0 ; round--) {
        inverse_shift_rows(state);
        inverse_subbytes(state, d_rsbox);
        add_round_key(state, round, expanded_key);
        inverse_mix_columns(state, d_m9, d_m11, d_m13, d_m14);
    }
    inverse_shift_rows(state);
    inverse_subbytes(state, d_rsbox);
    add_round_key(state, 0, expanded_key);    
}


__global__ void decipher_control(byte *file_in, byte *file_out, int padding, unsigned long *blocks, byte *expanded_key,
                                 byte *d_sbox, byte *d_rsbox, byte *d_m9, byte *d_m11, byte *d_m13, byte *d_m14)
{
    byte state[16];
    int block;

    block = blockIdx.x * blockDim.x + threadIdx.x;

    while(block < *blocks) {
        // Copy the block of memory from the input file to the state
        memcpy(state, file_in + block  * 16, 16 * sizeof(byte));

        // Invoke the cipher process for the corresponding block
        decipher(state, expanded_key, d_rsbox, d_m9, d_m11, d_m13, d_m14);

        // Check if it is necessary to remove padding from the last block
        if(block == ((*blocks) - 1) && padding > 0) {
             // Copy the encrypted block to the output file removing the padding
             memcpy(file_out + block  * 16, state, (16 - padding) * sizeof(byte));
        }
        else {
            // Copy the encrypted block to the output file
            memcpy(file_out + block  * 16, state, 16 * sizeof(byte));
        }
        block += gridDim.x * blockDim.x;
    }

}





int main(int argc, char *argv[]) {
    if(argc < 3) {
        printf("You must provide the name, route and extension of the file to be decrypted as well as the name for output\n");
        printf("Example: ./decryp files/test.aes files/test.txt\n");
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
    unsigned long *d_blocks;
    byte *d_sbox;
    byte *d_rsbox;
    byte *d_m9;
    byte *d_m11;
    byte *d_m13;
    byte *d_m14;
    byte *d_rcon;


    int byte_size = sizeof(byte);

    /* ------------ Allocate HOST memory ------------------------------*/
    key =           (byte*)          malloc(16  * byte_size);
    expanded_key =  (byte*)          malloc(176 * byte_size);
    file_in_size =  (long long*)     malloc(sizeof(long long));
    file_out_size = (long long*)     malloc(sizeof(long long));
    blocks =        (unsigned long*) malloc(sizeof(unsigned long));

    printf("AES Decipher using CUDA\n\n");
      
    /* --------  Starting encryption pre-process --------------------*/

    // Load the file to be encrypted
    *file_in_size = load_file(file_name, &file_in);
    if(*file_in_size == -1) {
        printf("Error trying to read the file");
        return 1;
    }
    
    // Compute the number of blocks needed and check whether the file has padding bytes at the end that need 
    // to be removed (it occurs when the cipher process added padding because the file size was not multiple of 16)
    *blocks = (*file_in_size) / 16;
    padding = file_in[0];

    // The size of the output file will be the input size after removing the padding and the first byte used to indicate padding
    *file_out_size = *file_in_size - padding - 1;

    // Allocate the memory for the output file
    file_out = (byte*)malloc((*file_out_size) * byte_size);

    // Read the key used to encrypt
    read_key_from_file(key);
    
    //  -----------------------      Allocate DEVICE memory   -----------------------
    cudaMalloc((void**)&d_file_in,      byte_size * (*file_in_size));
    cudaMalloc((void**)&d_file_out,     byte_size * (*file_out_size));
    cudaMalloc((void**)&d_key,          byte_size *  16);
    cudaMalloc((void**)&d_expanded_key, byte_size * 176);
    cudaMalloc((void**)&d_sbox,         byte_size * 256);
    cudaMalloc((void**)&d_rsbox,        byte_size * 256);
    cudaMalloc((void**)&d_m9,           byte_size * 256);
    cudaMalloc((void**)&d_m11,          byte_size * 256);
    cudaMalloc((void**)&d_m13,          byte_size * 256);
    cudaMalloc((void**)&d_m14,          byte_size * 256);
    cudaMalloc((void**)&d_rcon,         byte_size *  11);
    cudaMalloc((void**)&d_blocks,       sizeof(unsigned long));

    // GPU memory copy
    cudaMemcpy(d_file_in,      file_in,      byte_size * (*file_in_size),  cudaMemcpyHostToDevice);
    cudaMemcpy(d_key,          key,          byte_size *  16,              cudaMemcpyHostToDevice);
    cudaMemcpy(d_sbox,         SBOX,         byte_size * 256,              cudaMemcpyHostToDevice);
    cudaMemcpy(d_rsbox,        RSBOX,        byte_size * 256,              cudaMemcpyHostToDevice);
    cudaMemcpy(d_m9,           M9,           byte_size * 256,              cudaMemcpyHostToDevice);
    cudaMemcpy(d_m11,          M11,          byte_size * 256,              cudaMemcpyHostToDevice);
    cudaMemcpy(d_m13,          M13,          byte_size * 256,              cudaMemcpyHostToDevice);
    cudaMemcpy(d_m14,          M14,          byte_size * 256,              cudaMemcpyHostToDevice);
    cudaMemcpy(d_rcon,         RCON,         byte_size *  11,              cudaMemcpyHostToDevice);
    cudaMemcpy(d_blocks,       blocks,       sizeof(unsigned long),        cudaMemcpyHostToDevice);


    // Expand the key from 16 bytes to 176
    key_expansion <<<1, 1>>>(d_key, d_expanded_key, d_sbox, d_rcon);

    // For synchronization purposes
    cudaMemcpy(expanded_key, d_expanded_key, byte_size * 176, cudaMemcpyDeviceToHost);

    // Define the grid of threads used
    dim3 Threads(THREADS, THREADS);
    dim3 Thread_Blocks(THREAD_BLOCKS, THREAD_BLOCKS);

    printf("Starting decryption...\n");
    // Measure time
    double time_taken = 0;

    for(int i = 0; i < 10; i++) {
        start_timer();
        decipher_control <<< 128, 128>>> (d_file_in + 1, d_file_out, padding, d_blocks, d_expanded_key, d_sbox, d_rsbox, d_m9, d_m11, d_m13, d_m14);
        time_taken += stop_timer();
        cudaDeviceSynchronize();
    }

    printf("Done decryption. Time = %lf ms\n", time_taken/10.0);

    file_out[0] = padding;

    cudaMemcpy(file_out, d_file_out, byte_size * (*file_out_size), cudaMemcpyDeviceToHost);

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
    cudaFree(d_blocks);
    cudaFree(d_key);
    cudaFree(d_expanded_key);
    cudaFree(d_sbox);
    cudaFree(d_rsbox);
    cudaFree(d_rcon);
    cudaFree(d_m9);
    cudaFree(d_m11);
    cudaFree(d_m13);
    cudaFree(d_m14);
    
    return 0; 
}