#include <iostream>

#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/err.h>
#include "utils.h"

using namespace std;

int main(int argc, char *argv[])
{

	//This section uses BIOs to write a copy of infile.txt to outfile.txt
	//  and to send the hash of infile.txt to the command window.
	//  It is a barebones implementation with little to no error checking.

	//The SHA1 hash BIO is chained to the input BIO, though it could just
	//  as easily be chained to the output BIO instead.

	char infilename[] = "nguyen.txt";
	char outfilename[] = "outfile.txt";

	char* buffer[1024];

	BIO *binfile, *boutfile, *hash;
	binfile = BIO_new_file(infilename, "r");
	boutfile = BIO_new_file(outfilename, "w") ;
	hash = BIO_new(BIO_f_md());
	BIO_set_md(hash, EVP_sha1());

	//Chain on the input
	BIO_push(hash, binfile);

	//Chain on the output
	//BIO_push(hash, boutfile);

	int actualRead, actualWritten;

	while((actualRead = BIO_read(hash, buffer, 1024)) >= 1)
	{
		//Could send this to multiple chains from here
		actualWritten = BIO_write(boutfile, buffer, actualRead);
	}

	//Get digest
	char mdbuf[EVP_MAX_MD_SIZE];
	int mdlen = BIO_gets(hash, mdbuf, EVP_MAX_MD_SIZE);
	for(int i = 0; i < mdlen; i++)
	{
		//Print two hexadecimal digits (8 bits or 1 character) at a time
		printf("%02x", mdbuf[i] & 0xFF);
	}
	printf("\n");

	BIO_free_all(boutfile);
	BIO_free_all(hash);
	
	
	//C
	char privateKey[] = "rsaprivatekey.pem";
	char publicKey[] = "rsapublickey.pem";

	BIO *privKey, *pubKey;
	privKey = BIO_new_file(privateKey, "r");
	pubKey = BIO_new_file(publicKey, "r") ;

	RSA *rsa = PEM_read_bio_RSAPrivateKey(privKey, NULL, 0, NULL);

	//D
	unsigned char buff_two[128];
	unsigned char buff_final[128];
	memset(buff_two, 0, sizeof(buff_two));
	memset(buff_final, 0, sizeof(buff_final));
	int x = RSA_private_encrypt(117, (const unsigned char*)mdbuf, buff_two, rsa, RSA_PKCS1_PADDING);
	cout << endl << x;

	//E
	RSA *rsaTheSecond = PEM_read_bio_RSA_PUBKEY(pubKey, NULL, 0, NULL);
	
	//F
	
	int y = RSA_public_decrypt(128, buff_two, buff_final, rsaTheSecond, RSA_PKCS1_PADDING);
	cout << endl << y <<endl;
	//string output = buff2hex((const unsigned char*)mdbuf, 128);

	//G
	string output = buff2hex(buff_final, mdlen);
	cout << endl << output;
/*
	for(int i = 0; i < 128; i++)
	{
		//Print two hexadecimal digits (8 bits or 1 character) at a time
		printf("%02x", buff_two[i] & 0xFF);
	}
	printf("\n");
*/
	//RSA_print_fp(stdout, rsaTheSecond, 0);
	/*
	char buff_to[128]
	char buff_from[128] (hash value)
	char buffer for encrypted
	encrypt(length(buff_from))
		, buff_from
		, buff_to
		;
		,
	memcpy
	strcpy
	*/
	return 0;
}


//This function offers an example of chaining a DES cipher to a base 64 encoder
//  to a buffer to a file, using BIOs. Taken almost directly from the example code
//  in the book "Network Security with OpenSSL". The concepts should be useful
//  for preparing the RSA hash and signature.
//  Uncomment the function to try it out.
/*
int write_data(const char *filename, char *out, int len, unsigned char *key)
{
    int total, written;
    BIO *cipher, *b64, *buffer, *file;
    // Create a buffered file BIO for writing
    file = BIO_new_file(filename, "w") ;
    if (! file)
        return 0;
    // Create a buffering filter BIO to buffer writes to the file
    buffer = BIO_new(BIO_f_buffer( ));
    // Create a base64 encoding filter BIO
    b64 = BIO_new(BIO_f_base64( ));
    // Create the cipher filter BIO and set the key.  The last parameter of
    // BIO_set_cipher is 1 for encryption and 0 for decryption
    cipher = BIO_new(BIO_f_cipher( ));
    BIO_set_cipher(cipher, EVP_des_ede3_cbc( ), key, NULL, 1);
    // Assemble the BIO chain to be in the order cipher-b64-buffer-file

    BIO_push(cipher, b64);
    BIO_push(b64, buffer);
    BIO_push(buffer, file);
    // This loop writes the data to the file.  It checks for errors as if the
    // underlying file were non-blocking
    for (total = 0;  total < len;  total += written)
    {
        if ((written = BIO_write(cipher, out + total, len - total) ) <= 0)
        {
            if (BIO_should_retry(cipher) )
            {
                written = 0;
                continue;
            }
            break;
        }
    }
    // Ensure all of our data is pushed all the way to the file
    BIO_flush(cipher) ;
    // We now need to free the BIO chain. A call to BIO_free_all(cipher) would
    // accomplish this, but we' ll first remove b64 from the chain for
    // demonstration purposes.
    BIO_pop(b64) ;
    // At this point the b64 BIO is isolated and the chain is cipher-buffer-file.
    // The following frees all of that memory
    BIO_free(b64) ;
    BIO_free_all(cipher) ;
	return 0;
}
*/
