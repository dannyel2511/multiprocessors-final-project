import java.lang.*;

public class AES_decipher {
   // Attributes
   private int[] file_in;
   private int[] file_out;
   private int[] key = new int[16];
   private int[] expanded_key = new int[176];
   private long file_in_size;
   private long file_out_size;
   private long blocks;
   private int padding;
   
   AES_decipher(int fi[], int k[]) {
      this.key = k;                             // Initialize the key with the data received
      this.file_in_size = fi.length;            // Get the size of the input file
      this.blocks = (this.file_in_size) / 16;   // Compute the number of blocks needed and check whether the file requires
      this.padding = fi[0];                     // Get the indicated bytes of padding

      this.file_in = new int[(int)this.file_in_size];   // Allocate memory for the input file
      java.lang.System.arraycopy(fi, 1, this.file_in, 0, fi.length - 1); // Initialize the input file with the data received without the first (byte to indicate padding)

      this.file_out_size = this.file_in_size - padding - 1;  // The size of the output file will be the input size after removing the 
                                                             // padding and the first byte used to indicate padding

      this.file_out = new int[(int)this.file_out_size]; // Allocate memory for the output file
      this.key_expansion();                             // Expand the key from 16 to 176 bytes (11 blocks for the rounds)
   }

   // Get the resulted file after encryption
   public int[] get_file_out() {
      return this.file_out;
   }

   // Get the data from the auxiliary matrices
   int get_sbox(int pos)     { return My_Utils.SBOX[pos];}
   int get_rsbox(int pos)    { return My_Utils.RSBOX[pos];}
   int mul_9   (int a)       { return My_Utils.M9[a];  }
   int mul_11  (int a)       { return My_Utils.M11[a]; }
   int mul_13  (int a)       { return My_Utils.M13[a]; }
   int mul_14  (int a)       { return My_Utils.M14[a]; }
   int get_rcon(int a)       { return My_Utils.RCON[a];}

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
      int aux = this.file_in[idx];
      for(int i = 0;i < 3;i++) {
         this.file_in[idx + i] = this.file_in[idx + i + 1];
      }
      this.file_in[idx + 3] = aux;
   }
   // Circular shift to the right by one position
   void rotateRight(int idx) {        
       int aux = this.file_in[idx + 3];    
       for(int i = 3;i > 0;i--) {
           this.file_in[idx + i] = this.file_in[idx + i-1];
       }
       this.file_in[idx + 0] = aux;
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
   private void inverse_subbytes(int idx) {
       int i, j;
       for(i=0;i<4;i++) 
           for(j=0;j<4;j++) 
               this.file_in[idx + (j * 4 + i)] = get_rsbox(this.file_in[idx + (j * 4 + i)]);
   }

   // To change the order in each row performing shifts to the left
   private void inverse_shift_rows(int idx) {    
      rotateRight(idx + 4);

      rotateRight(idx + 8);
      rotateRight(idx + 8);

      rotateRight(idx + 12);
      rotateRight(idx + 12);
      rotateRight(idx + 12);
   }

   // To perform a substitution that uses finite fields arithmetic over GF(2^^8).
   private void inverse_mix_columns(int idx) {
       int i, a0, a1, a2, a3;
       for(i=0;i<4;i++) {
           a0 = this.file_in[idx + (i * 4 + 0)];
           a1 = this.file_in[idx + (i * 4 + 1)];
           a2 = this.file_in[idx + (i * 4 + 2)];
           a3 = this.file_in[idx + (i * 4 + 3)];

           this.file_in[idx + (i * 4 + 0)] = mul_14(a0)  ^ mul_11(a1) ^ mul_13(a2) ^ mul_9( a3);
           this.file_in[idx + (i * 4 + 1)] = mul_9( a0)  ^ mul_14(a1) ^ mul_11(a2) ^ mul_13(a3);
           this.file_in[idx + (i * 4 + 2)] = mul_13(a0)  ^ mul_9( a1) ^ mul_14(a2) ^ mul_11(a3);
           this.file_in[idx + (i * 4 + 3)] = mul_11(a0)  ^ mul_13(a1) ^ mul_9( a2) ^ mul_14(a3);   
       }
   }

   // To decipher the block of data using the AES algorithm
   private void decipher(int idx) {    
      int round=0;    
      this.add_round_key(10, idx);
      for(round = 9; round > 0 ; round--) {
         this.inverse_shift_rows(idx);
         this.inverse_subbytes(idx);
         this.add_round_key(round, idx);
         this.inverse_mix_columns(idx);
      }
      this.inverse_shift_rows(idx);
      this.inverse_subbytes(idx);
      this.add_round_key(0, idx);
   }
   // Main function of the decipher process.
   public void decipher_control() {
      // Index to control the index of the current block to cipher
      int idx = 0;

      for(int block = 0; block < this.blocks; block++) {
         idx = block * 16;
         // Invoke the decipher process for the corresponding block
         this.decipher(idx);
         if(block == this.blocks - 1 && padding > 0) {
         // Check if it is necessary to remove padding from the last block         if(block == this.blocks - 1 && this.padding > 0) {
            for(int i = 0; i < (16 - padding); i++) {
               file_out[idx + i] = file_in[idx + i];
            }
         }
         else {
           // Copy the deciphered block to the output file
           for(int i = 0; i < 16; i++) {
              file_out[idx + i] = file_in[idx + i];
           }
         }
      }
   }
}