/* 
  secure_ais_protocol.cpp
  @authors Ahmed Aziz, Pietro Tedeschi, Savio Sciancalepore, Roberto Di Pietro
  @Description: A program for implementing the SecureAIS Protocol PoC
  @version 1.0 17/01/19
**/

#include "secure_ais_protocol.h"

/***********************************************************
 *                                                         *
 * Functions required for generating ECQV certificates     *
 *                                                         *
 * *********************************************************/

//algorithm to calculate base 2 log of big numbers
int adhoc_log2(BIG i) {
    int n = 0;
    BIG input, div, compareValue;
    BIG_zero(div);
    BIG_zero(compareValue);
    BIG_zero(input);
    BIG_inc(div, 2);
    BIG_copy(input, i);

    while (true){
        BIG_sdiv(input, div);
        if (BIG_comp(input, compareValue) == 0)
            break;
        ++n;
    };
    return n;
}

/**	@brief Create an ECQV certificate
 *
 *  @param octet *certificate store output certificate
 *  @param octet *public_key Public key that will become encoded in certificate
 *  @param int MMSI unique MMSI ID for maritime equipment
 *  @return binary string of message 6
 */
void encode_certificate(octet *certificate, octet *public_key, int MMSI){
    //Add public key to certificate
    OCT_copy(certificate, public_key);
    //Add validity time, 32 bits
    unsign32 validity = (unsign32)time(NULL); 
    OCT_jint(certificate, validity, sizeof(validity));
    //Add MMSI, MMSI itself is 30 bits but this will change into 32 bits
    OCT_jint(certificate, MMSI, sizeof(MMSI));
}

/**	
 *  @brief Hash function to calculate, e = Hn(CertU) from 2.3, SEC4, v1.0
 *  @param certificate, a ptr to where ECQV certificate is stored
 *  @param e, BIG number where e would be stored
 *  @return void
 */
void Hn(octet *certificate, BIG e){
    //create a temp octet
    char tempOctet_certificate_size[2 * field_size_EFS + 1 + 16];
    octet tempOctet = {0, sizeof(tempOctet_certificate_size), tempOctet_certificate_size};
    //copy certificate into temp octet
    OCT_copy(&tempOctet, certificate);
    //Use hash function
    SPhash(MC_SHA2, SHA256, &tempOctet, certificate);
    //Set big number r to curve order
    BIG r;
    BIG_rcopy(r, CURVE_Order); 
    //Set temp to leftmost bits
    int len = adhoc_log2(r)/8;
    tempOctet.len = len;
    //Convert temp octet to big number stored in e
    BIG_fromBytesLen(e, tempOctet.val, len);
}

/**	
 *  @brief generate an ECQV certificate
 *  @param RNG will be used a random number generator
 *  @param Ship struct data having keys
 *  @param  CAprivate private key of certificate authority
 *  @param  CApublic public key of certificate authority
 *  @param MMSI, unique 30 bit ID of ship requesting certificate
 *  @return int telling whether process succeeded (0) or failed
 */
int genECQVCert(csprng *RNG, ship_state_t *Ship, octet* CAprivate, octet* CApublic, int MMSI){

    int res; 
    char k0[field_size_EGS], kG0[2 * field_size_EFS + 1];
    octet k0private = {0, sizeof(k0), k0};
    octet kG0public = {0, sizeof(kG0), kG0};
    BIG e={0};
    ECP PU, kG, QCA, PU_copy;
    while(true){
        //3.4 Certificate Generation Process: Cert Generate
        //Generate an EC key pair (k, kG)
        ECP_KEY_PAIR_GENERATE(RNG, &k0private, &kG0public);
        res = ECP_PUBLIC_KEY_VALIDATE(&kG0public);
        if (res != 0)
        {
            printf("kG Public Key is invalid!\n");
            return res;
        }

        //Compute the elliptic curve point PU = RU + kG, convert to ECP from octet so to add later
        ECP_fromOctet(&PU, &Ship->public_key);
        ECP_fromOctet(&kG, &kG0public);
        ECP_add(&PU, &kG);
       // printf("\nPU_ECP = 0x");
       // ECP_output(&PU);

        char pu_octet[2 * field_size_EFS + 1];
        octet PU_octet = {0, sizeof(pu_octet), pu_octet};
        ECP_toOctet(&PU_octet, &PU, false);
      //  printf("\nPU_octet = 0x");
      //  OCT_output(&PU_octet);
        
        encode_certificate(&Ship->ECQVCert, &PU_octet, MMSI);
   //     printf("certificate = 0x");
   //     OCT_output(certificate);
        
        Hn(&Ship->ECQVCert, e);

       // std::cout<<"\ne = ";
       // BIG_output(e);

        //8. If ePU + QCA = O, where O is the identity element,
        res = ECP_fromOctet(&QCA, CApublic);
        if (res != 1)
        {
            printf("ECP from octet is invalid!\n");
            return 0;
        }
    //  printf("\nPU_ECP = 0x");
    //  ECP_output(&PU);
        ECP_copy(&PU_copy, &PU);
        ECP_mul(&PU_copy, e);
        ECP_add(&PU_copy, &QCA);
        //std::cout<<"\nECPisinf:"<< ECP_isinf(&PU);
        if(!ECP_isinf(&PU)) 
            break;
    }

    //9. Compute the integer r = ek + dCA (mod n).
    DBIG ek={0}, temp={0};
    BIG k={0},dCA={0}, curveOrder={0};
    BIG_rcopy(curveOrder, CURVE_Order);
    BIG_fromBytes(k, k0private.val);
    BIG_fromBytes(dCA, CAprivate->val);
    BIG_mul(ek, k, e);
   // printf("\nek:");
   // BIG_doutput(ek);
   // printf("\nek1:");
   // BIG_output(ek1);
    BIG_dscopy(Ship->r, dCA);
    BIG_dadd(temp, ek, Ship->r);
   // printf("\nr:");
   // BIG_doutput(temp);
    BIG_dmod(Ship->r, temp, curveOrder);
  //  printf("\nr:");
  //  BIG_doutput(r);

     //3.5 Certificate Public Key Extraction Process: Cert PK Extraction
    char PK_extract_size[2 * field_size_EFS + 1];
    octet PK_extract = {0, sizeof(PK_extract_size), PK_extract_size}; 

    //Join bytes till public key size
    OCT_jbytes( &PK_extract, Ship->ECQVCert.val, 2 * field_size_EFS + 1);
    res = ECP_PUBLIC_KEY_VALIDATE(&PK_extract);
    if (res != 0)
    {
        printf("Extracted Public Key from certificate is invalid!\n");
        return res;
    }
  //  printf("\nPublic key extract: \n");
  //  OCT_output(&PK_extract);
 
    ECP QU, ECP_PU_extract;
    res = ECP_fromOctet(&QCA, CApublic);
    if (res != 1)
    {
        printf("ECP from octet is invalid!\n");
        return 0;
    }
    ECP_fromOctet(&ECP_PU_extract, &PK_extract);
    //printf("\nECP_PU_extract!\n");
    //ECP_output(&ECP_PU_extract);

    ECP_copy(&QU, &ECP_PU_extract);
    ECP_mul(&QU, e);
    ECP_add(&QU, &QCA);


    //3.6 Processing the Response to a Cert Request: Cert Reception/Validation
    //Compute the private key dU = r + ekU(mod n).
    BIG ku={0}, finaldu={0};
    DBIG eku={0}, du={0}, dutemp={0};    
    BIG_fromBytes(ku, Ship->private_key.val);
    BIG_mul(eku, ku, e);
    BIG_dadd(dutemp, eku, Ship->r);

    BIG_dmod(du, dutemp, curveOrder);
  //  printf("\ndu:");
  //  BIG_doutput(du);
  //  printf("\ndu:");
    BIG_sdcopy(finaldu, du);

   // printf("\nr_BIG:");
   // BIG_output(r_BIG);
    Ship->r_private_key.len = field_size_EFS;
    BIG_toBytes(Ship->r_private_key.val, finaldu);
 //   printf("\nPrivate key data from BIG: \n");
 //   OCT_output(r_private_key);

    //BIG_output(finaldu);
    char qPub0[2 * field_size_EFS + 1], qPub1[2 * field_size_EFS + 1];
 
    octet QpubOrig = {0, sizeof(qPub0), qPub0};
    octet Qpub1 = {0, sizeof(qPub1), qPub1};

    ECP G;
    ECP_generator(&G);
    //ECP_output(&G);
    ECP_mul(&G, finaldu);
    ECP_toOctet(&Qpub1, &G, false);
    ECP_toOctet(&QpubOrig, &QU, false);


    res = ECP_PUBLIC_KEY_VALIDATE(&Qpub1);
    if (res != 0)
    {
        printf("ECP Public Key is invalid!\n");
        return -1;
    }
/*
    printf("\nOrig. ECP Public Key is:\n");
    OCT_output(&QpubOrig);
    printf("\nRegen. ECP Public Key is:\n");
    OCT_output(&Qpub1);
*/
    if (!OCT_comp(&QpubOrig, &Qpub1))
    {
        printf("*** ECQV-Cert-gen Failed\n");
        return -1;
    }

    return 0;
}

/*  Functions used for AIS process itself   */

/**	@brief Create an AIS Message of type 6
 *
 *  @param int src_MMSI
 *  @param int dest_MMSI
 *  @param int msg_sequence
 *  @return binary string of message 6
 */
string encode_ais_message_6(int src_MMSI, int dest_MMSI, int msg_sequence, string payload){ 
    string type = std::bitset<6>(6).to_string(); 
    string repeat = "00";
    string src_mmsi = std::bitset<30>(src_MMSI).to_string();

    //increment sequence number if more messages
    string seq_number = std::bitset<2>(msg_sequence).to_string();//"00";
    string dst_mmsi = std::bitset<30>(dest_MMSI).to_string();
    string retransmit_flag = "0";
    string spare = "0";
    string dac = "0000000000"; //10 bit
    string FI = "000000"; //6 bits
    //application bits are custom bits for self use
    string application_bits = std::bitset<12>(0).to_string(); 
  
    return type+repeat+src_mmsi+seq_number+dst_mmsi+retransmit_flag+spare+dac+FI+payload;
}

/**	
 *  @brief Convert hex string to binary string
 *  @param string &s 
 *  @return binary string
 */
string hextobin(const string &s){
    string out;
    for(auto i: s){
        uint8_t n;
        if(i <= '9' and i >= '0')
            n = i - '0';
        else
            n = 10 + i - 'A';
        for(int8_t j = 3; j >= 0; --j)
            out.push_back((n & (1<<j))? '1':'0');
    }

    return out;
}

/**	
 *  @brief Convert binary string to hex string
 *  @param string &s 
 *  @return hex string
 */
string bintohex(const string &s){
    string out;
    for(uint i = 0; i < s.size(); i += 4){
        int8_t n = 0;
        for(uint j = i; j < i + 4; ++j){
            n <<= 1;
            if(s[j] == '1')
                n |= 1;
        }

        if(n<=9)
            out.push_back('0' + n);
        else
            out.push_back('a' + n - 10);
    }

    return out;
}

/**	
 *  @brief Setup precompute keys to be used by SecureAIS protocol 
 *  @param key struct where keys will be stored 
 *  @return void
 */
void setup_keys(precompute_key_data_t &key){
    if (SECURITY_LEVEL == 0){
        key.security_level = SECURITY_LEVEL;
        key.CAprivate = (char *)"1331564f3ebcbdeb6859c0419ea9d2a639b1688a"; 
        key.CApublic = (char *)"047fd127e05c9f68d490af867a414518e23a930bbf0abae2a2d0b74b213b14125d4d99e77bb0ac9b03";
        key.Ship_1_ECQVCert = (char *)"04f4db18a9c27e8c945220c70292ce59c0287141836dc1dded614763c40107c47abce6c900963ad0a65e1b77ae075bcd15";
        key.Ship_1_r_private_key = (char *)"4de5fa6478f07e79c7cd49427173dd905fa0ce35";
        key.Ship_2_ECQVCert = (char *)"04c2a9c9ea21e28d49b3933a2c22824a7cf2ed28040877b447258d127af59a7e2a8aa23757e392d7315e1b77ae075bcd15";  
        key.Ship_2_r_private_key = (char *)"6efbd2a97306198e6c8d8572baeccf5a3f6752de";  
    }
    else if (SECURITY_LEVEL == 1){
        key.security_level = SECURITY_LEVEL;
        key.CAprivate = (char *)"1331564f3ebcbdeb6859c0419ea9d2a639b1688a"; 
        key.CApublic = (char *)"047fd127e05c9f68d490af867a414518e23a930bbf0abae2a2d0b74b213b14125d4d99e77bb0ac9b03";
        key.Ship_1_ECQVCert = (char *)"04f4db18a9c27e8c945220c70292ce59c0287141836dc1dded614763c40107c47abce6c900963ad0a65e1b77ae075bcd15";
        key.Ship_1_r_private_key = (char *)"4de5fa6478f07e79c7cd49427173dd905fa0ce35";
        key.Ship_2_ECQVCert = (char *)"04c2a9c9ea21e28d49b3933a2c22824a7cf2ed28040877b447258d127af59a7e2a8aa23757e392d7315e1b77ae075bcd15";  
        key.Ship_2_r_private_key = (char *)"6efbd2a97306198e6c8d8572baeccf5a3f6752de";  
    }
    else if (SECURITY_LEVEL == 2){
        key.security_level = SECURITY_LEVEL;
        key.CAprivate = (char *)"0e177b6ffe996e7b1c5e9b324c3b38360ec4f4136487d9236ce54ba4bac7e0ef"; 
        key.CApublic = (char *)"041326ceeb291614a79ecdc74738f7767e29be9991a47aa6d2003df30fc9ff639533e8f8341a669413404364c3d25d7139f472a1bd47b3fd0ce393cdddff65a3e5";
        key.Ship_1_ECQVCert = (char *)"04045f3201f86c5f7164681ff7c7a96774c87bb23db61203e001bc8c88a517ad5722d0d9730574b10c8068b2915766a6f3da47c2c77e800bb37c3b1ef507a0a0d15e1b23b7075bcd15";
        key.Ship_1_r_private_key = (char *)"084dc9a28d085294193096a5a50f3a1dd871969ebfb1dffd727272d7e2e58053";
        key.Ship_2_ECQVCert = (char *)"04545b0f3454926f036828ef0e17727535ccc32c316aebcc405d694f16fbafb86c0831fd0a94bdde1cfb389a2d0c9d33cc94d33c3eb08f73f0f99acf083ffef6675e1b25e8075bcd15";  
        key.Ship_2_r_private_key = (char *)"0f81a50628b383c3510f13e18e5118796dc4e7ad188dc4febf9abf219e200195"; 
    }
    else if (SECURITY_LEVEL == 3){
        key.security_level = SECURITY_LEVEL;
        key.CAprivate = (char *)"3ab8a46d397d1dac96310ce979f4c9d36504c67168761f5115aad094cff9dc9739c1b8623284bb4d81ec3a97d5832e98"; 
        key.CApublic = (char *)"04978241fdd07420e9be441eb320fb58a886b4b0b936ee2c1520bd05a2527f771d4c37bdb686cdec999e6f959d4a715afc1fa67f8e0476a046fb2b342dcc0e932815f910cc273b453c6f44d8b1e42c71577111ac738da503179209781920b25568";
        key.Ship_1_ECQVCert = (char *)"0475ccf1c1870fbcde03e0d38a8c1a1b902c6d38f146e6c689a9c450bb2f8e47c045a4f200cdf5b7fb5da84584a57afc2444d07d4ca1d6227929b898303c633c2d805f2005ad795e5c0d304d5d7241db04d9302bc9142e7f1ef8505e2271ffca7c5e1b7d9b075bcd15";
        key.Ship_1_r_private_key = (char *)"e878964f47de571ed82b806587281d3fc645e91a44ca7a953a6c38d60296c569a9bf15ae0662bb84018509e2e477b5d2";
        key.Ship_2_ECQVCert = (char *)"041cd499f2c40d97c8894ecb42da59e95aad2bc7e01d1863faac628b6206336b89b667c480e79f8581a57d9db0afcc72b0360a4cacba2b31ee820f94bf3eeadc87462473dc96e77e7f02b56e6cf3a5e2ea46e929f6fd01fed96d4e94af217f0af85e1b7d9b075bcd15";  
        key.Ship_2_r_private_key = (char *)"92d1edf1c5b7a7e244103e6e44526a16f3241ac628ee9639dbb1d9303b55a85fa308979fb4f2ef0db8e1813a90cbf6d8"; 
    }else if (SECURITY_LEVEL == 4){
        key.security_level = SECURITY_LEVEL;
        key.CAprivate = (char *)"0000f9c896cd876f440c0bfc99bdb3094bd4eb5a4d3c90ee52d7d8a1baccb294f22d7f255a55bc5c1f786ce61c811aad6eff2257838a0f5506449e0d17cd63d53495"; 
        key.CApublic = (char *)"0401daaa1e95db0588a242560e8b67afdf098bf707958966d8d4a2bf1bf75c9fbea3e0b2153faba40ed855b5dceaeadb36075d7506fc5e84d50f15bf8adc2c80457992004eb79fc92c0c407b666b878d7e7b6f2ee4a5c068060b8f22fa1ebb62a8d3e2c1f6e3b26f335a2b4f8bfb75a3e6d607b8c70d14ae2d95df8759eeb4c98302fc20cb";
        key.Ship_1_ECQVCert = (char *)"0401dc676ff138fd66abfd721f89bd9d97b983a6a8713c3abd21da62d9eff36eef188c2b4b757dacfd3e0729eabd2c731cba275a1bd81c0d7fd565d6084ff25473660d0129ad89ee81c2c2626ce1ac5566c0841134e738b7b0ae752158c357bc79fe693dae48efa4fe12c610c971fc84002eeb6d24eb4ab10afe6a25783159cfc3ff34fbe95e1b7e94075bcd15";
        key.Ship_1_r_private_key = (char *)"00257010c654d76db89273c1ebabab2e7e20bfbf70f6239324a5c2da6293f57da2dc3e1cb29aec78807fab0718f799beafb5a46b3e36093cdc2e22bb2e3ab5565f6c";
        key.Ship_2_ECQVCert = (char *)"04010aa7522fc7ac907d11387f6e5251f77acabe981b086b3e3583c79938e5a42bd5f004d6b4d44dc81a3bf160c2f204d2d151f1098571df1d85878f9f4d363dda7b7a00aed12b5d1f0695cbb7502ad908b159384551cfc5cda5a4eae304f9630b0b3ba0ab9a78191919f11eef4a88cb5c86d5b35d626c85a056c5a25203fba5fd90a63c2d5e1b7e94075bcd15";  
        key.Ship_2_r_private_key = (char *)"01a2e759d1335bd9a375508584362e0d2cd891594f7df28c9e9c904c4165f28ad26afcdd6e27d4bb1aae530f9fb5e190819dac146f0ae06d2512548db480afc29255"; 
    }else{
        return;
    }
}

void test2_write_message(string header, long long microseconds ){
    if(TEST == 2){
        if( header.empty() )
            return;
        ofstream outfile;
        outfile.open("test_2.csv", ios::out | ios::app );
        outfile << header << ", " << microseconds << endl;
        // close the opened file.
        outfile.close();
    }
    return; 
}