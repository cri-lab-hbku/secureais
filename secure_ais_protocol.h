/* 
  secure_ais_protocol.h 
  @authors Ahmed Aziz, Pietro Tedeschi, Savio Sciancalepore, Roberto Di Pietro
  @Description: A program for implementing the SecureAIS Protocol PoC
  @version 1.0 17/01/19
**/
#ifndef SECURE_AIS_SECURE_AIS_H_
#define SECURE_AIS_SECURE_AIS_H_

#include <string>
#include <bitset>
#include <iostream>
#include <fstream>
#include <chrono>
#include <sys/types.h> 
#include <arpa/inet.h> 
#include <sys/socket.h>
#include <random>

#define MAX_SLOTS 3
#define MAX_SLOTS_DATA_SIZE 62 // 62 bytes

 //0 means production, 1 for test 1, 2 for test 2
#ifndef TEST
#define TEST 0
#endif
#ifndef PORT_RECEIVE
#define PORT_RECEIVE 51999
#endif
#ifndef PORT_SEND
#define PORT_SEND 5200
#endif
#ifndef GEN_KEYS
#define GEN_KEYS false
#endif

/***********************************************************
 *                                                         *
 * Macros created for adding required security level files *
 *                                                         *
 * *********************************************************/

#ifndef SECURITY_LEVEL
#define SECURITY_LEVEL 0
#endif

#ifdef SECURITY_LEVEL
#if  SECURITY_LEVEL == 0
    //160 bit - No security
    #include "core-master/cpp/ecdh_SECP160R1.h"
    #define field_size_EFS EFS_SECP160R1
    #define field_size_EGS EGS_SECP160R1
    #define AESKEY AESKEY_SECP160R1
    using namespace B160_56;
    using namespace SECP160R1;
#elif  SECURITY_LEVEL == 1
    //160 bit - 80 bit security
    #include "core-master/cpp/ecdh_SECP160R1.h"
    #define field_size_EFS EFS_SECP160R1
    #define field_size_EGS EGS_SECP160R1
    #define AESKEY AESKEY_SECP160R1
    using namespace B160_56;
    using namespace SECP160R1;
#elif SECURITY_LEVEL == 2
    //256 bit - 128 bit security
    #include "core-master/cpp/ecdh_ED25519.h"
    using namespace B256_56;
    using namespace ED25519;
    #define field_size_EFS EFS_ED25519
    #define field_size_EGS EGS_ED25519
    #define AESKEY AESKEY_ED25519
#elif SECURITY_LEVEL == 3
    #include "core-master/cpp/ecdh_NIST384.h"
    using namespace B384_56;
    using namespace NIST384;
    #define field_size_EFS EFS_NIST384
    #define field_size_EGS EGS_NIST384
    #define AESKEY AESKEY_NIST384
#elif SECURITY_LEVEL == 4
    #include "core-master/cpp/ecdh_NIST521.h"
    using namespace B528_60;
    using namespace NIST521;
    #define field_size_EFS EFS_NIST521
    #define field_size_EGS EGS_NIST521
    #define AESKEY AESKEY_NIST521
#endif
#endif

using namespace core;
using namespace std;

/***********************************************************
 *                                                         *
 *      Structures created for abstraction purposes        *
 *                                                         *
 * *********************************************************/

/**
 * @struct ship_state_t	
 * @brief A structure to represent data stored by a Ship for SecureAIS Protocol
 */
 
typedef struct ship_state_s{
    //Variables storing data for self
    char s0[field_size_EGS], s1[field_size_EGS], w0[2 * field_size_EFS + 1], w1[2 * field_size_EFS + 1], z0[field_size_EFS];
    char certificate_size[2 * field_size_EFS + 1 + 16],  recvd_cert_size[2 * field_size_EFS + 1 + 16], key[AESKEY*2 + 1], l_key[AESKEY + 1];
    octet private_key = {0, sizeof(s0), s0};
    octet public_key = {0, sizeof(w0), w0};
    octet session_key = {0, sizeof(key), key};
    octet l_session_key = {0, sizeof(l_key), l_key};

    DBIG r={0};//private key data for ECQV
    octet r_private_key = {0, sizeof(s1), s1};//private key data for ECQV
    octet ECQVCert = {0, sizeof(certificate_size), certificate_size};
    string nonce = "";
    char auth_tag_size[SHA256];
    octet auth_tag = {0, sizeof(auth_tag_size), auth_tag_size};
    string message_sent="";
    octet DH_shared_key = {0, sizeof(z0), z0};
    
    //Variables storing other party data    
    octet recvd_cert = {0, sizeof(recvd_cert_size), recvd_cert_size};
    octet recvd_public_key = {0, sizeof(w1), w1};
    string message_received ="";
    string received_nonce="";
    char rcvd_auth_tag_size[SHA256];
    octet rcvd_auth_tag = {0, sizeof(rcvd_auth_tag_size), rcvd_auth_tag_size};
}ship_state_t;


/**
 * @struct precompute_key_data_t		
 * @brief A structure to define precomputed keys for different security levels
 */
typedef struct precompute_key_data_s{
    int security_level;
    char *CAprivate;
    char *CApublic;
    char *Ship_1_ECQVCert;
    char *Ship_1_r_private_key;
    char *Ship_2_ECQVCert;
    char *Ship_2_r_private_key;
}precompute_key_data_t;


/***********************************************************
 *                                                         *
 *                Function prototypes                      *
 *                                                         *
 * *********************************************************/

/*  Functions that were just there for generation of implicit ECQV certificates 
using the process defined SEC4, v1.0    */

/**	
 *  @brief encode an ECQV certificate
 *  @param octet store output certificate
 *  @param octet public_key that will become encoded in certificate
 *  @return binary string of message 6
 */
void encode_certificate(octet *certificate, octet *public_key, int MMSI);

/**	
 *  @brief algorithm to calculate base 2 log of big numbers
 *  @param BIG i number whose base 2 log is to be found
 *  @return base 2 log of input number
 */
int adhoc_log2(BIG i);

/**	
 *  @brief Hash function to calculate, e = Hn(CertU) from 2.3, SEC4, v1.0
 *  @param certificate, a ptr to where ECQV certificate is stored
 *  @param e, BIG number where e would be stored
 *  @return void
 */
void Hn(octet *certificate, BIG e);

/**	
 *  @brief generate an ECQV certificate
 *  @param RNG will be used a random number generator
 *  @param Ship struct data having keys
 *  @param  CAprivate private key of certificate authority
 *  @param  CApublic public key of certificate authority
 *  @param MMSI, unique 30 bit ID of ship requesting certificate
 *  @return int telling whether process succeeded (0) or failed
 */
int genECQVCert(csprng *RNG, ship_state_t *Ship, octet* CAprivate, octet* CApublic, int MMSI);

/*  Functions used for AIS process itself   */

string encode_ais_message_6(int src_MMSI, int dest_MMSI, int msg_sequence, string payload);

/**	
 *  @brief Convert hex string to binary string
 *  @param string &s 
 *  @return binary string
 */
string hextobin(const string &s);

/**	
 *  @brief Convert binary string to hex string
 *  @param string &s 
 *  @return hex string
 */
string bintohex(const string &s);
/**	
 *  @brief Setup precompute keys to be used by SecureAIS protocol 
 *  @param key struct where keys will be stored 
 *  @return void
 */
void setup_keys(precompute_key_data_t &key);

/**	
 *  @brief Function used to get times for test 2
 *  @param string header title to write in file
 *  @param microseconds, time in microseconds to be written in file 
 *  @return void
 */
void test2_write_message(string header, long long microseconds );

#endif //SECURE_AIS_SECURE_AIS_H_