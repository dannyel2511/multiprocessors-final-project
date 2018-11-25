#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <cuda_runtime.h>
#include "my_utils.h" // Contains the precomputed matrices used for the AES algorithm
#define byte unsigned char

// Global variables
byte *sbox;
byte *m2;
byte *m3;   
byte *rcon;

/*************************************** CPU ********************************************/
/****************************** Auxiliary functions *************************************/

// To read a file containing the key used to cipher
void read_key_from_file(byte *key) {
   FILE *fp;
   byte *key_file = "../key.txt";
   byte buffer[20];
   byte i;

   if((fp = fopen(key_file, "rb")) == NULL){
       printf(" Cannot open input file: %s\n",key_file);
       printf(" Exiting program...\n");
       return;
   }

   fgets(buffer, 17, (FILE*)fp);
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
void write_file(byte *file_out_name, byte *file_out, long long file_out_size) {
    FILE *f_o; // Pointer to the file

    // Open file
    if((f_o = fopen((const char*)file_out_name,"wb")) == NULL)  {
        printf("Error trying to open the file %s\n", file_out_name);
        return;
    }

    fwrite(file_out, sizeof(byte), file_out_size, f_o);

    fclose(f_o);
}


/*************************************** GPU *****************************************************/
/*************************************** Auxiliary functions *************************************/

// Print the data contained in the state
void print_state(byte *state) {
   for(int i = 0; i < 4; i++) {
      for (int j = 0; j < 4; j++) {
         printf("%0X ", state[i*4+j]);
      }
      printf("\n");
   }
}

// Get the data from the auxiliar matrices
byte get_sbox(byte pos) { return sbox[pos];}
byte mul_2(byte a)      { return m2[a]; }
byte mul_3(byte a)      { return m3[a]; }

// Circular shift to the left by one position
void rotateLeft(byte *A) {    
    byte i;
    byte aux = A[0];    
    for(i=0;i<3;i++) {
        A[i] = A[i+1];
    }
    A[3] = aux;
}
/*************************************** AES functions *************************************/
// To expand the key using the SBOX matrix
void key_expansion(byte *key, byte *expanded_key) {
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
                temp[a] = get_sbox(temp[a]);
            }
            temp[0] =  temp[0] ^ rcon[i];
            i++;
        }
        for(a = 0; a < 4; a++) {
            expanded_key[c] = expanded_key[c-16] ^ temp[a];
            c++;
        }
    }
}

// To merge the expanded key with the data of the state
void add_round_key(byte *state, int round, byte *expanded_key) {
    // The data block used in the expanded key depends on the number of round
    int i, j;
    for(i=0;i<4;i++) {
        for(j=0;j<4;j++) {
            state[i * 4 + j] ^= expanded_key[round*16 + i*4 + j];
        }        
    }
}

// To substitute the value of the state with the corresponding value in the SBOX matrix
void subbytes(byte *state) {
    byte i, j;
    for(i=0;i<4;i++) 
        for(j=0;j<4;j++) 
            state[j * 4 + i] = get_sbox(state[j * 4 + i]);
}

// To change the order in each row performing shifts to the left
void shift_rows(byte *state) {    
    byte i;
    byte temp[4];

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
void mix_columns(byte *state) {
    byte i, a0, a1, a2, a3;
    for(i=0;i<4;i++) {
        a0 = state[i * 4 + 0];
        a1 = state[i * 4 + 1];
        a2 = state[i * 4 + 2];
        a3 = state[i * 4 + 3];

        state[i * 4 + 0] = mul_2(a0) ^ mul_3(a1) ^ a2 ^ a3;
        state[i * 4 + 1] = mul_2(a1) ^ mul_3(a2) ^ a0 ^ a3;
        state[i * 4 + 2] = mul_2(a2) ^ mul_3(a3) ^ a0 ^ a1;
        state[i * 4 + 3] = mul_2(a3) ^ mul_3(a0) ^ a1 ^ a2;        
    }
}

// To cipher the block of data using the AES algorithm
void cipher(byte *state, byte *expanded_key) {    
    int round=0;    
    add_round_key(state, round, expanded_key);    
    for(round=1; round < 10 ; round++) {
        subbytes(state);
        shift_rows(state);
        mix_columns(state);
        add_round_key(state, round, expanded_key);
    }
    subbytes(state);
    shift_rows(state);
    add_round_key(state, 10, expanded_key);    
}


void cipher_control(byte *file_in_name, byte *file_in, byte *file_out, long long file_size, unsigned long blocks, byte *expanded_key) {
    byte state[16];
    unsigned long block;
    int padding, res;

    // Check if the size of the input file is multiple of 16
    res = file_size % 16;
                 
    for(block = 0; block < blocks; block++) {
        memcpy(state, file_in + block * 16, 16 * sizeof(byte));
        // Check if it is necessary to add padding to the last block
        if(block == blocks - 1 && res != 0) {
            padding = 16 - res;
            for(int i = res;i < res + padding;i++) {
                state[i] = 0x00;
            }
        }

        // Invoke the cipher process for the corresponding block
        cipher(state, expanded_key);

        // Copy the encrypted block to the output file
        memcpy(file_out + block * 16, state, 16 * sizeof(byte));             
    }
}





int main(int argc, char *argv[]) {
    if(argc < 3) {
        printf("You must provide the name, route and extension of the file to be encrypted as well as the name for output\n");
        printf("Example: ./encryp files/test.jpg files/test.aes\n");
        return 0;
    }
    // Name of the input and output files
    byte *file_name     = (byte*)argv[1];
    byte *out_file_name = (byte*)argv[2];

    byte *file_in;               // Stores the binary data of the file to be encrypted
    byte *file_out;              // Stores the binary data of the encrypted file
    byte *key;                   // Stores the key provided by the user 
    byte *expanded_key;          // The key after the expansion algorithm
    long long file_in_size;      // Size of the input file
    long long file_out_size;     // Size of the output file
    unsigned long blocks;        // Number of blocks to divide the file
    unsigned long padding;       // Number of padding bytes to add
    int byte_size = sizeof(byte);// Get the size of one byte

    // Allocate memory
    key =           (byte*) malloc(byte_size *  16);
    expanded_key =  (byte*) malloc(byte_size * 176);
    sbox =        (byte*) malloc(byte_size * 256);
    m2 =          (byte*) malloc(byte_size * 256);
    m3 =          (byte*) malloc(byte_size * 256);
    rcon =        (byte*) malloc(byte_size *  11);

   // Copy data from precomputed matrices
    memcpy(sbox, SBOX, byte_size * 256);
    memcpy(m2,     M2, byte_size * 256);
    memcpy(m3,     M3, byte_size * 256);
    memcpy(rcon, RCON, byte_size *  11);
       
    /* Starting encryption pre-process */
    file_in_size = load_file(file_name, &file_in);  // Load the file to be encrypted
    
    
    blocks = (file_in_size) / 16;                  // Compute the number of blocks needed and check whether the file requires
                                                    // a byte of padding at the end (when it is not a multiple of 16)
    padding = 0;
    if(file_in_size % 16 != 0) {
        padding = 16 - (file_in_size) % 16;
        (blocks)++;
    }
    // The size of the output file will be a multiple of 16 + 1 because of the byte at the beginning to indicate the padding
    file_out_size = blocks * 16 + 1;

    file_out = (byte*)malloc(file_out_size * byte_size);  // Allocate the memory for the output file
    
    file_out[0] = padding;              // Write in the first byte of the output the number of padding bytes
     
    read_key_from_file(key);            // Read the key used to encrypt
    key_expansion(key, expanded_key);   // Apply the algorithm to expand the key

    printf("Starting encryption...\n");
    // Measure time
    double time_taken = 0;
    
    for(int i = 0; i < 10; i++) {
      start_timer();
      cipher_control(file_name, file_in, file_out + 1, file_in_size, blocks, expanded_key);
      time_taken += stop_timer();
    }
    
    printf("Done encryption. Time = %lf ms\n", time_taken/10.0);

    write_file(out_file_name, file_out, file_out_size);

    
    free(file_in);
    free(file_out);
    free(key);
    free(expanded_key);
    free(rcon);
    free(sbox);
    free(m2);
    free(m3);    
    return 0; 
}
