import java.lang.*;

public class AES_cipher implements Runnable {
   // Attributes
   private static int[] file_in;
   private static int[] file_out;
   private static int[] key = new int[16];
   private static int[] expanded_key = new int[176];
   private static long file_in_size;
   private static long file_out_size;
   private static long blocks;
   private long start, end;
   
   AES_cipher(int fi[], int k[]) {
      this.key = k;                             // Initialize the key with the data received
      int padding = 0;

      this.file_in_size = fi.length;            // Get the size of the input file
      
      this.blocks = (file_in_size) / 16;        // Compute the number of blocks needed and check whether the file requires
      if(this.file_in_size % 16 != 0) {         // a int of padding at the end (when it is not a multiple of 16)
        padding = 16 - (int)(this.file_in_size % 16);
        this.blocks++;
      }

      this.file_in_size = this.blocks * 16;              // Adjust the input file to a multiple of 16
      this.file_in = new int[(int)this.file_in_size];    // Allocate memory for the input file
      java.lang.System.arraycopy(fi, 0, this.file_in, 0, fi.length);                      // Initialize the input file with the data received

      file_out_size = this.file_in_size + 1;             // The size of the output file will be the same as input, 
                                                         // but adding 1 because of the byte to indicate padding

      this.file_out = new int[(int)this.file_out_size];  // Allocate memory for the output file

      this.file_out[0]   = (int)padding;                 // Write to the first byte of the output the number of padding bytes

      this.key_expansion();                              // Expand the key from 16 to 176 bytes (11 blocks for the rounds)
   }
   // Initializes the object assigning the start block and end block to process
   AES_cipher(long st, long e) {
      this.start = st;
      this.end   = e;
   }

   // Get the resulted file after encryption
   public int[] get_file_out() {
      return this.file_out;
   }

   // Get the data from the auxiliary matrices
   int get_sbox(int pos) { return (int)My_Utils.SBOX[pos];}
   int    mul_2(int   a) { return (int)My_Utils.M2[a];    }
   int    mul_3(int   a) { return (int)My_Utils.M3[a];    }
   int get_rcon(int   a) { return (int)My_Utils.RCON[a];  }

   /* Functions to perform operations over the state */
   // Print the data contained in the state
   private void print_state(int idx) {
      System.out.println("Current state:");
      for(int i = 0; i < 4; i++) {
         for (int j = 0; j < 4; j++) {
            System.out.printf("%x ", this.file_in[idx + (i*4+j)]);
         }
         System.out.println();
      }
   }

   // Circular shift to the left by one position
   private void rotateLeft(int idx) {
      int aux= file_in[idx];
      for(int i = 0;i < 3;i++) {
         file_in[idx + i] = file_in[idx + i + 1];
      }
      file_in[idx + 3] = aux;
   }
   /*************************************** AES functions *************************************/
   // To expand the key using the SBOX matrix
   private void key_expansion() {
       int temp[] = new int[4];
       int c=16;
       int j, a, i=1;
       for(j=0; j < 16; j++) {
           this.expanded_key[j] = key[j];
       }
       while(c < 176) {
           for(a = 0; a < 4; a++) {
               temp[a] = this.expanded_key[a+c-4];
           }
           if(c % 16 == 0) {
               // Rotate left
               int aux = temp[0];
               for(int x = 0;x < 3;x++) {
                  temp[x] = temp[x + 1];
               }
               temp[3] = aux;
               // End rotate left
               for(a = 0; a < 4; a++) {
                   temp[a] = get_sbox(temp[a]);
               }
               temp[0] =  temp[0] ^ get_rcon(i);
               i++;
           }
           for(a = 0; a < 4; a++) {
               this.expanded_key[c] = this.expanded_key[c-16] ^ (int)temp[a];
               c++;
           }
       }
   }
   // To merge the expanded key with the data of the state
   private void add_round_key(int round, int idx) {
       // The data block used in the expanded key depends on the number of round
       for(int i = 0;i < 4;i++) {
           for(int j = 0;j < 4;j++) {
               this.file_in[idx + (i * 4 + j)] ^= this.expanded_key[(round * 16) + (i * 4) + j];
           }        
       }
   }

   // To substitute the value of the state with the corresponding value in the SBOX matrix
   private void subbytes(int idx) {
       int i, j;
       for(i=0;i<4;i++) 
           for(j=0;j<4;j++) 
               this.file_in[idx + (j * 4 + i)] = get_sbox(this.file_in[idx + (j * 4 + i)]);
   }

   // To change the order in each row performing shifts to the left
   private void shift_rows(int idx) {    
      rotateLeft(idx + 4);

      rotateLeft(idx + 8);
      rotateLeft(idx + 8);

      rotateLeft(idx + 12);
      rotateLeft(idx + 12);
      rotateLeft(idx + 12);
   }

   // To perform a substitution that uses finite fields arithmetic over GF(2^^8).
   private void mix_columns(int idx) {
       int i, a0, a1, a2, a3;
       for(i=0;i<4;i++) {
           a0 = this.file_in[idx + (i * 4 + 0)];
           a1 = this.file_in[idx + (i * 4 + 1)];
           a2 = this.file_in[idx + (i * 4 + 2)];
           a3 = this.file_in[idx + (i * 4 + 3)];

           this.file_in[idx + (i * 4 + 0)] = mul_2(a0) ^ mul_3(a1) ^ a2 ^ a3;
           this.file_in[idx + (i * 4 + 1)] = mul_2(a1) ^ mul_3(a2) ^ a0 ^ a3;
           this.file_in[idx + (i * 4 + 2)] = mul_2(a2) ^ mul_3(a3) ^ a0 ^ a1;
           this.file_in[idx + (i * 4 + 3)] = mul_2(a3) ^ mul_3(a0) ^ a1 ^ a2;        
       }
   }

   // To cipher the block of data using the AES algorithm
   private void cipher(int idx) {    
      int round=0;    
      this.add_round_key(round, idx);
      for(round=1; round < 10 ; round++) {
         this.subbytes(idx);
         this.shift_rows(idx);
         this.mix_columns(idx);
         this.add_round_key(round, idx);
      }
      this.subbytes(idx);
      this.shift_rows(idx);
      this.add_round_key(10, idx);
   }
   // Main function of the cipher process.
   public void run() {
      int padding, res;
      // Index to control the index of the current block to cipher
      int idx = 0;
      // Check if the size of the input file is multiple of 16
      res = (int)this.file_in_size % 16;

      for(int block = (int)this.start; block < this.end; block++) {
         idx = block * 16;
         // Check if it is necessary to add padding to the last block
         if(block == this.blocks - 1 && res != 0) {
            padding = 16 - res;
            for(int i = res;i < res + padding;i++) {
                this.file_in[idx + i] = 0x00;
            }
         }

         // Invoke the cipher process for the corresponding block
         this.cipher(idx);

         // Copy the encrypted block to the output file
         for(int i = 0; i < 16; i++) {
            file_out[(idx + 1) + i] = file_in[idx + i];
         }
      }
   }


}