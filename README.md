# HKF- A Memory Hard Password Key Derivation Function

A flexible memory hard key derivation function without unnecessary overhead

Tags: fast memory hard function, password hashing, memory hard key stretching, memory hard key strengthening, scrypt, bcrypt, sequential memory hard function, kdf.

<b>Introduction</b>

Currently, a single GPU cluster <a href="http://hackaday.com/2012/12/06/25-gpus-brute-force-348-billion-hashes-per-second-to-crack-your-passwords/">can break</a> an estimated 1000 billions (10^12) passwords/hashes per second, far less than what a state attacker or a hackers team can do with specialized hardware (ASIC, FPGA), supercomputers or botnets networks. Basically, a password of 16-17 characters (80 bits of entropy) can be broken within hours by brute force, and we are not even in quantum age.

A 16 characters password has 16 * 5 bits of entropy, so there are 2^80 (~10^23) total variants. Considering the success of breaking 10^12 passwords/s on a single GPU cluster, then a botnets network can do this one milion times faster (10^6), so we can test 10^18 passwords per second. In 10 hours, this becomes 3600 x 10 more = almost 10^5 faster. So basically 10^23 variants can be tested in 10 hours.... basically all variants of a 16 characters password, not to mention that probablly only half have to be tested, and quantum computers are close.

Things are going worse because hashes are usually generated on a single CPU, while the world CPUs number is increasing, so the availability for attackers who may use CPUs from smartphones, smart TV or any connected smart "thing".

A system that allows trial of low entroy inputs against hashes or access is vulnerable from the start. Either the attacker has obtained the hashes file and tries to recover the passwords, or he tries to decrypt the communication by generating the session keys from the low entropy passwords, this is the weakest link in the chain and not the encryption/hashing algorithm. We are not talking here about side attack channels, when the attacker has access to the memory, most likely he already recovered the password in plain text or he has screenshots of mouse clicks.

Because the low entropy input (password) is easiest to attack by brute force, instead of attacking a session key of 256 bits, <b>the developers should generate passwords hashes slower, salted and memory intensive</b>. This because GPUs use a lot of small cores to perform massive parallel computing attack, if each core would use a lot of memory for the algorithm they will run out of memory soon when they try to break the hash.

There are several known such key stretching functions, like scrypt, I tried to create one without unnecessary ultra strong intermediarry cryptographic memory diffusion and focus on flexibility, simplicity and quality of output, which I ensured to be non-biased, collision free and cryptographic safe. Saving CPU processing power from memory generator leads to more memory usage and more rounds in less time at hash generation.

<b>HKF Design</b>

There are 3 simple parts, obvious in source code too:

1. Fast memory pool generation<br>
The memory is generated progressively, row after row, so any further redesign involves recalculations. The generator starts with a cryptographic safe pseudorandom buffer and adds low entroy difussion, the speed is more important at this stage.

2. Stir the memory pool<br>
This will mitigate the risk of algorithm redesign to use less memory, since random access involve far more recalculations.

3. Mix the final key with random values from the memory pool.<br>
The final hash is obtained by combining the result with the output of a stream cipher, so its basically a strong encryption.

Currently, on a single core of a first generation i7 a 256 bytes hash requires 1Gb of memory and one million rounds.
The beauty of this design is that any stream cipher can be used also any step can be configurated or improved.

<b>Usage</b>

void GetHashKey(unsigned char* password, int passwordLength, unsigned char* salt, int saltLength, int megabytes, int rounds, unsigned char* output)

IN: 
- password, up to 256 bytes
- salt, any size, choose something decent like 64 byte, for example
- megabytes, desired memory usage, in megabytes,
- rounds - round trips to memory <br>
(choose the last two depending on how much time you can afford to compute the password hash)

OUT:
- 256bytes hash (output), you can use it all, part of it, or hash it further with some fast hash like SHA512 to make it smaller.

