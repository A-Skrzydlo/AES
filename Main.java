import static com.sun.org.apache.xalan.internal.xsltc.compiler.sym.EOF;

/**
 * Created by root on 13.01.17.
 */
public class Main {
    public static void main (String [] args){
        System.out.println(AES128.Encrypt("Here put the plaintext which will be encrypted", "ThisIs16BitsKey!"));
    }
}

class AES128 {

    public static String  Encrypt (String plainText, String key){

        /*
                Converting String input to Int array with dec-system elements
         */
        String cypherText = "";
        char [] plainTextC = plainText.toCharArray();
        char [] keyC = key.toCharArray();
        int [] plainTextInt = new int[plainText.length()];
        int [] keyInt = new int [16];
        int [] state = new int [16];
        int i = 0;

        if (keyC.length > 16){
            System.out.println("!!! Key length must be not more than 16 bytes");
            return "";
        }
        while (keyC.length > i){
            keyInt[i] = (int) keyC[i];
            i++;
        }
        i = 0;
        while (plainTextC.length > i){
            plainTextInt[i] = (int) plainTextC[i];
            i++;
        }

        //Creating key schedule
        int [][] Subkeys = new int[11][16];
        Subkeys = keySchedule(keyInt);



        for (int j = 0, stateIndex = 0; j < plainTextC.length; j++, stateIndex ++){

            if( j % 16 == 0 && j != 0){
                cypherText += encryptionCore(state, Subkeys);
                state = clearState(state);
                stateIndex = 0;
            }
            state[stateIndex] = plainTextInt[j];
        }
        cypherText += encryptionCore(state, Subkeys);



        return cypherText;

    }

    private static int [] clearState(int [] state){
        for (int i =0; i <16; i++){
            state[i] = 0;
        }
        return state;
    }

    private  static String encryptionCore (int [] state, int [][] Subkeys){

        int round = 0;
        //Initial round
        state = KeyAdd(Subkeys[round], state);
        //Round 1 -9
        for (round = 1; round < 10; round++){
            state = ByteSub(state);
            state = ShiftRows(state);
            state = MixCol(state);
            state = KeyAdd(Subkeys[round],state);
        }
        //Final round
        state = ByteSub(state);
        state = ShiftRows(state);
        state = KeyAdd(Subkeys[10],state);

        // conversion int[] to string
        String output = "";
        for (int i = 0; i < 16; i++){
            output += Integer.toHexString(state[i]) + " ";
        }
        return output + "\n";
    }

    private static int [] ByteSub(int [] input){
        int [] output = new int[input.length];

        int sbox[] = {  0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
                        0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
                        0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
                        0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
                        0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
                        0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
                        0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
                        0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
                        0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
                        0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
                        0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
                        0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
                        0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
                        0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
                        0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
                        0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16 };

        int i = 0;
        while (i < input.length){
            output [i] = sbox[input[i]];
            i++;
        }

        return output;
    }

    private static int[] ShiftRows(int [] input){
        int [] output = new int[input.length];

        output[0] = input[0];
        output[1] = input[5];
        output[2] = input[10];
        output[3] = input[15];

        output[4] = input[4];
        output[5] = input[9];
        output[6] = input[14];
        output[7] = input[3];

        output[8] = input[8];
        output[9] = input[13];
        output[10] = input[2];
        output[11] = input[7];

        output[12] = input[12];
        output[13] = input[1];
        output[14] = input[6];
        output[15] = input[11];

        return output;
    }

    private static int [] MixCol(int [] input){
        int [] output = new int[input.length];
            output = matrixMultip(input);
        return output;
    }

    private static int [] matrixMultip (int [] B){
        int [] D = new int[B.length];

        D[0] = ModularReduction(B[0] << 1) ^ ModularReduction(B[1] << 1 ^ B[1]) ^ B[2] ^ B[3];
        D[1] = B[0] ^ ModularReduction(B[1] << 1) ^ ModularReduction(B[2] << 1  ^ B[2]) ^ B[3];
        D[2] = B[0] ^ B[1] ^ ModularReduction(B[2] << 1) ^ ModularReduction(B[3] << 1 ^ B[3]);
        D[3] = ModularReduction(B[0] << 1 ^ B[0]) ^ B[1] ^ B[2] ^ ModularReduction(B[3] << 1);

        D[4] = ModularReduction(B[4] << 1) ^ ModularReduction(B[5] ^ B[5] << 1)  ^ B[6] ^ B[7];
        D[5] = B[4] ^ ModularReduction(B[5] << 1) ^ ModularReduction(B[6] << 1  ^ B[6]) ^ B[7];
        D[6] = B[4] ^ B[5] ^ ModularReduction(B[6] << 1) ^ ModularReduction(B[7] << 1 ^ B[7]);
        D[7] = ModularReduction(B[4] << 1 ^ B[4]) ^ B[5] ^ B[6] ^ ModularReduction(B[7] << 1);

        D[8] = ModularReduction(B[8] << 1) ^ ModularReduction(B[9] ^ B[9] << 1)  ^ B[10] ^ B[11];
        D[9] = B[8] ^ ModularReduction(B[9] << 1) ^ ModularReduction(B[10] << 1  ^ B[10]) ^ B[11];
        D[10] = B[8] ^ B[9] ^ ModularReduction(B[10] << 1) ^ ModularReduction(B[11] << 1 ^ B[11]);
        D[11] = ModularReduction(B[8] << 1 ^ B[8]) ^ B[9] ^ B[10] ^ ModularReduction(B[11] << 1);

        D[12] = ModularReduction(B[12] << 1) ^ ModularReduction(B[13] ^ B[13] << 1)  ^ B[14] ^ B[15];
        D[13] = B[12] ^ ModularReduction(B[13] << 1) ^ ModularReduction(B[14] << 1  ^ B[14]) ^ B[15];
        D[14] = B[12] ^ B[13] ^ ModularReduction(B[14] << 1) ^ ModularReduction(B[15] << 1 ^ B[15]);
        D[15] = ModularReduction(B[12] << 1 ^ B[12]) ^ B[13] ^ B[14] ^ ModularReduction(B[15] << 1);



        return D;
    }

    private static int [][] keySchedule (int [] key) {
        //int key [] = {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c};
        int rcon[] = {0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36};
        int sbox[] = {
                0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
                0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
                0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
                0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
                0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
                0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
                0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
                0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
                0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
                0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
                0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
                0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
                0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
                0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
                0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
                0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16 };

        // filling null row of array with main key
        int [][] subKeys = new int[11][16];
        for (int i=0; i<16; i++){
            subKeys[0][i] = key[i];
        }
        for (int numbOfSubkey = 1; numbOfSubkey < 11; numbOfSubkey++){
            // Rotation & byte substitution & xor with rcon-function & xor with first word of previous subkey (first 32 bits)
            subKeys[numbOfSubkey][0]= sbox[subKeys[numbOfSubkey-1][13]] ^ rcon[numbOfSubkey] ^ subKeys[numbOfSubkey-1][0];
            subKeys[numbOfSubkey][1]= sbox[subKeys[numbOfSubkey-1][14]] ^ rcon[0] ^ subKeys[numbOfSubkey-1][1];
            subKeys[numbOfSubkey][2]= sbox[subKeys[numbOfSubkey-1][15]] ^ rcon[0] ^ subKeys[numbOfSubkey-1][2];
            subKeys[numbOfSubkey][3]= sbox[subKeys[numbOfSubkey-1][12]] ^ rcon[0] ^ subKeys[numbOfSubkey-1][3];
            //computing 3 left words
            for (int bitPosit = 4; bitPosit < 16; bitPosit++){
                subKeys[numbOfSubkey][bitPosit] = subKeys[numbOfSubkey-1][bitPosit] ^ subKeys[numbOfSubkey][bitPosit-4];
            }
        }
        return subKeys;
    } //ok

    private static int ModularReduction (int a){
        // reducing  ? C[i] > 256 by AES polynomial P(x) = x^8 + x^4 + x^3 + x + 1 == 283(10)

        int shift = 0;

            int xor = 0;
            if (a >= 256){
                return a ^ 0x11b;

               /* //counting shifts in C[i]
                int tempC = a;
                while (tempC > 0){
                    tempC = tempC >> 1;
                    shift++;
                }
                shift -= 9;

                tempC = a;

                int j = shift;
                while(j >= 0){
                    xor = tempC ^ (283 << j);
                    int tempShift = 0;
                    int tempC1 = xor;
                    while (tempC1 > 1){
                        tempC1 >>= 1;
                        tempShift++;
                    }
                    tempC = xor;
                    j = tempShift - 8;
                }

                a = xor;*/

            }

        return a;
    } //ok

    private static int [] KeyAdd ( int [] key, int [] state){
        int [] newState = new int[16];
        int temp;
        for (int i=0; i<16; i++){
            temp = state[i] ^ key[i];
            newState[i] = temp;
        }
        return newState;
    } //ok
}
