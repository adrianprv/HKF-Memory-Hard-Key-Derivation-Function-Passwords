
// HKF - Memory Hard Key Derivation Function v 1.5
// Adrian Pirvu - October 14, 2015
//
// A memory hard key derivation function without overhead
// INPUT: password - up to 256 bytes; salt - no limitation;  
// megabytes: memory you intend to use; rounds: memory pickup rounds;
// OUTPUT: stretched key (current 256 bytes)
// 3.7 seconds with 1Gb of memory and 1 million rounds on single core of a first generation i7 CPU (release)
// IMPORTANT: No cycles wasted to generate memory difussion, the diffusion is obtained in the end, 
// during memory round trips calculations
// The random access in the end makes possible usage of ANY amount of memory, 
// redesign avoided through the random mix of the memory box
// In the end I ensure that the output is random, ireversible and non-biased by mixing with a stream cipher output
// Basically we have a FillMemory(), StirMemory() PickRandom() flow
// Tweaked Arc4 used as a one way random generator, but any stream cipher can be used (ex Spritz, Salsa20, Chacha)
// No side attacks considered, if the attacker has access to your RAM 
// then an activity tracking RAT already took your password or screenshots of your mouse clicks
// Tags: fast memory hard function, password hashing, memory hard key stretching, 
// memory hard key strengthening, scrypt, bcrypt, sequential memory hard function



#include "stdafx.h"
//#include <string.h>
//#include <time.h>
//#include <windows.h>


extern "C"
{

	unsigned int i = 0, j = 0;
	unsigned char s[256], k[256];

	void RngInit(unsigned char* key, int keyLength, unsigned char* salt, int saltLength);
	unsigned char RngNextByte();
	unsigned int RngNextInt();
	__declspec(dllexport) void GetHashKey(unsigned char* password, int passwordLength, unsigned char* salt, int saltLength, int megabytes, int rounds, unsigned char* output);


	
	//unsigned int TEST_MEGABYTES = 1024;
	//unsigned int TEST_ROUNDS = 1000000;

	//// main function, for test purpose
	//int main(int argc, char * argv[])
	//{
	//	const char* password = "monkey";
	//	const char* salt = "superman";
	//	unsigned char output[256];
	//	GetHashKey((unsigned char*) password, strlen(password), (unsigned char*) salt, strlen(salt), TEST_MEGABYTES, TEST_ROUNDS, output);
	//	//FILE* file = fopen("d:\\key.dat", "wb");
	//	//fwrite((void*) key, 1, 100000000, file);
	//	//fflush(file);
	//	//fclose(file);
	//}



	// return a hashable strengthen key of desired length from password and salt
	__declspec(dllexport) void GetHashKey(unsigned char* password, int passwordLength, unsigned char* salt, int saltLength, int megabytes, int rounds, unsigned char* output)
	{
		// dinamically allocates memory 4 * 1024 * megabytes
		int ROWS = 4 * 1024 * megabytes; // each row is 256 bytes (256 * 4 * 1024 = 1k * 1024 = 1M)
		int COLUMNS = 64; // * 4 bytes per int = 256 bytes
		unsigned int* box = new unsigned int[ROWS * COLUMNS];
		unsigned int tmp = 0;

		// init the random engine and get a temporary key
		RngInit(password, passwordLength, salt, saltLength);
		unsigned int key[64];
		for (int col = 0; col < 64; col++)
			key[col] = RngNextInt();

		// reinit the engine for safety and get a start key and the session salt
		RngInit((unsigned char*) key, 256, salt, saltLength);
		unsigned int pepper[64];
		for (int col = 0; col < 64; col++)
		{
			key[col] = RngNextInt();
			pepper[col] = RngNextInt();
			box[col] = key[col]; // first row is the start key
		}

		//clock_t start = clock();

		// fills the memory fast
		unsigned int random = key[34] * key[56] + key[62];
		for (int row = 1; row < ROWS; row++)
		{
			// breaks the row random and switch parts
			int index = box[(row - 1) * COLUMNS + 56] & 0xFF;
			memcpy((unsigned char*) &box[row * COLUMNS] + index, (unsigned char*) &box [(row - 1) * COLUMNS], 256 - index);
			memcpy((unsigned char*) &box[row * COLUMNS], (unsigned char*) &box [(row - 1) * COLUMNS] + 256 - index, index);

			// xor each number with the session salt and a pseudorandom number
			for (int col = 0; col < 64; col++)
			{
				random = 2147483629 * random + 2147483587; // maybe something with longer period?
				box[row * COLUMNS + col] = (box[row * COLUMNS + col] + pepper[col]) ^ random;
			}
		}

		// stir the memory box (one time but possible severral times and aligned to char)
		for (int row = 1; row < ROWS; row++)
		{
			int newRow = box[row * COLUMNS + 37] % ROWS; // get a random row
			int index1 = box[row * COLUMNS + 31] % 64;   // and two random indexes
			int index2 = box[row * COLUMNS + 46] % 64;   
			tmp = box[row * COLUMNS + index1];  // then switch values
			box[row * COLUMNS + index1] = box[newRow * COLUMNS + index2];
			box[newRow * COLUMNS + index2] = tmp;
		}

		// start with the last row to avoid precalculations and algo redesign
		for (int col = 0; col < 64; col++)
			key[col] = box[(ROWS - 1) * COLUMNS + col];


		// intensively get random integers from memory and mix them into the pseudorandom key
		for (int rnd = 0; rnd < rounds; rnd++)
			for (int col = 0; col < 64; col++)
			{
				// RngNextByte();
				i = (i + 1) % 256;
				j = (j + s[i]) % 256;
				tmp = s[i];
				s[i] = s[j];
				s[j] = tmp;
				unsigned int sum1 = (s[i] + s[j]);
				unsigned int column = sum1 % 64; // random column
				sum1 = sum1 % 256;

				// RngNextByte();
				i = (i + 1) % 256;
				j = (j + s[i]) % 256;
				tmp = s[i];
				s[i] = s[j];
				s[j] = tmp;
				unsigned int sum2 = (s[i] + s[j]) % 256;
				unsigned int row = (key[col] + sum2 + i + j) % ROWS; // random row

				// mix current key with value at (row, column)
				unsigned int total = (sum1 << (16 + (sum2 % 9))) + (sum2 << (sum1 % 9));
				key[col] = (key[col] + total) ^ (box [row * COLUMNS + column] + pepper[col]);
			}

		//clock_t diff = clock() - start;
		//char message[1000];
		//float seconds = ((float) diff) / CLOCKS_PER_SEC;
		//sprintf(message, "Seconds: %0.3f\r\n\0", seconds);
		//OutputDebugStringA(message);


		// build safe output, actually an encryption with a stream cipher
		for (int col = 0; col < 256; col++)
			output[col] = RngNextByte() ^ ((unsigned char*) key)[col];

		// cleanup
		for (int col = 0; col < COLUMNS; col++)
		{
			box[(ROWS - 1) * COLUMNS + col] ^= box[(ROWS - 1)* COLUMNS + col];
			key[col] ^= key[col];
			pepper[col] ^= pepper[col];
		}
		ROWS = 0;
		COLUMNS = 0;
		for (int col = 0; col < 256; col++)
		{
			s[col] = 0;
			k[col] = 0;
		}
		i = i = 0;

		delete[] box;
	}




	// init RNG engine 
	void RngInit(unsigned char* key, int keyLength, unsigned char* salt, int saltLength)
	{
		unsigned char tmp = 0;
		unsigned int saltval = 0;

		i = j = 0;
		for (i = 0; i < 256; i++)
		{
			s[i] = i;
			k[i] = key[i % keyLength];
		}

		j = 0;
		for (i = 0; i < 256; i++)
		{
			j = (j + s[i] + k[i]) % 256;
			tmp = s[i];
			s[i] = s[j];
			s[j] = tmp;
			k[i] = 0;
		}

		// discard start to bypass key scheduler flaws, also mix the salt
		i = j = 0;
		for (int idx = 0; idx < 4000 + s[251] + saltLength; idx++)
		{
			saltval = saltLength > 0 ? salt[idx % saltLength] : 0;
			i = (i + 1) % 256;
			j = (j + s[i] + saltval) % 256;
			tmp = s[i];
			s[i] = s[j];
			s[j] = tmp;
		}
	}




	// obtain a random byte from Rng engine
	unsigned char RngNextByte()
	{
		unsigned char tmp = 0;

		i = (i + 1) % 256;
		j = (j + s[i]) % 256;
		tmp = s[i];
		s[i] = s[j];
		s[j] = tmp;

		return (s[i] + s[j]) % 256;
	}




	// obtain a random int from Rng engine
	unsigned int RngNextInt()
	{
		unsigned char tmp = 0;
		unsigned char output[4];
		for (int idx = 0; idx < sizeof(int); idx++)
			output[idx] = RngNextByte();

		return *((unsigned int*) output);
	}


}



