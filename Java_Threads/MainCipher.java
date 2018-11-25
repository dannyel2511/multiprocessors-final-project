import java.io.File;
import java.io.IOException;
import java.nio.file.Files;

class MainCipher {
   private static final int MAXTHREADS = Runtime.getRuntime().availableProcessors();
   // Function to read a file from internal storage
   public static byte[] read_file(String file_name) throws IOException {
      File file = new File(file_name);
      return Files.readAllBytes(file.toPath());
   }

   // Function to write a file to internal storage
   public static void write_file(String file_name, int[] data) throws IOException {
      File file = new File(file_name);
      byte[] file_out = new byte[data.length];
      for(int i = 0; i < data.length; i++) {
         file_out[i] = (byte)data[i];
      }
      Files.write(file.toPath(), file_out);
   }

   


   public static void main(String args[]) {
      int[]  file_in  = null;          // Binary data of the file to be ciphered
      byte[] file_aux = null;          // Auxiliary array to store data
      int[]  file_out = null;          // Binary data of the file ciphered
      int[]  key      = new int[16];   // Binary data of the key used to cipher
      AES_cipher ac = null;            // Object used to cipher
      long startTime, stopTime;        // Variables to measure the time
      double time_taken = 0;           // To accumulate the time taken
      long aes_blocks;
      long thread_blocks;
      Thread[] threads;

      if(args.length < 2) {
         System.out.println("You must provide the name, route and extension of the file to be encrypted as well as the name for output\n");
         System.out.println("Example: ./encryp files/test.jpg files/test.aes\n");
         return;
      }

      String file_in_name  = args[0];                    // Name and route of the input file
      String file_out_name = args[1];                    // Name and route of the output file

      try{
         file_aux = read_file("../key.txt");             // Read the key used to cipher
         for(int i = 0; i < 16; i++) {                   // Copy the data read from file to Java array
            key[i] = (int)file_aux[i];
         }

         file_aux = read_file(file_in_name);             // Read the file to be ciphered
         file_in  = new int[file_aux.length];            // Allocate memory for the input file
         
         for(int i = 0; i < file_aux.length; i++) {      // Copy the data read from file to Java array
            file_in[i] = (int)file_aux[i];
            if(file_in[i] < 0) {
               file_in[i] = 256 + file_in[i];            }
         }
         
      } catch(IOException e) {
         System.out.println("Error trying to read the file" + e);
      }


      // Get the number of blocks needed
      aes_blocks = file_in.length / 16;
      if(file_in.length % 16 != 0) aes_blocks++;

      thread_blocks = aes_blocks / MAXTHREADS;
      threads = new Thread[MAXTHREADS];

      System.out.println("Starting encryption process...");

      for(int j = 0; j < 10; j++) {                      // Execute 10 times to measure properly the runtime
         ac = new AES_cipher(file_in, key);              // Instantiate the object to cipher
         startTime = System.currentTimeMillis();         // Start timer to measure the runtime
         for(int thr = 0; thr < MAXTHREADS; thr++) {     // Assign the work to the threads
            if(thr < MAXTHREADS - 1) {
               threads[thr] = new Thread(new AES_cipher(thr * thread_blocks, (thr + 1) * thread_blocks));
            }
            else {
               threads[thr] = new Thread(new AES_cipher(thr * thread_blocks, aes_blocks));
            }
         }

         for(int thr = 0; thr < MAXTHREADS; thr++) {
            threads[thr].start();
         }

         for(int thr = 0; thr < MAXTHREADS; thr++) {
            try {
               threads[thr].join();
            } catch (InterruptedException e) {
               e.printStackTrace();
            }
         }
         stopTime  = System.currentTimeMillis();        // Stop timer
         time_taken += (stopTime - startTime);          // Accumulate time

         for(int i = 0; i < file_aux.length; i++) {      // Copy the data read from file to Java array
            file_in[i] = (int)file_aux[i];
            if(file_in[i] < 0) {
               file_in[i] = 256 + file_in[i];
            }
         }
      }

      System.out.println("Encryption process finished. Avg time = " + time_taken/10.0);

      file_out = ac.get_file_out();                      // Get the file ciphered
      
      System.out.println("Saving file...");
      try {
         write_file(file_out_name, file_out);
      } catch(IOException e) {
         System.out.println("Error trying to write the file" + e);
      }
      System.out.println("File saved.");
   }

}