/* 
  main.cpp 
  @authors Ahmed Aziz, Pietro Tedeschi, Savio Sciancalepore, Roberto Di Pietro
  @Description: A program for implementing the SecureAIS Protocol PoC
  @version 1.0 17/01/19

  Compile command, add flag -DPORT_SEND or -DPORT_RECEIVE to set another port, 
  -DGEN_KEYS= true or false to set whether to generate keys or not
  g++ -O2 main.cpp -DSECURITY_LEVEL=1 ./secure_ais_protocol.cpp ./ais_receiver/*.c core-master/cpp/core.a -o main
**/

#include "secure_ais_protocol.h"
#include "ais_receiver/ais_rx.h"
#include "core-master/cpp/randapi.h"


//WARNING, Moving below functions can break this program!!!!

/**	
 *  @brief read an ais message from socket coming from GNURadio
 *  @param fd1 file descriptor being used by read socket
 *  @param ais struct that will store AIS messages
 *  @param  message_count, index where current message will be stored
 *  @return void
 */
void read_ais(int fd1, ais_message_t *ais, int message_count){
        AISConfiguration ais_config;
        load_configuration(NULL, &ais_config);
        ais[message_count].fd = fd1;
        ais[message_count].d.seqnr = 0;
        read_ais_message(&ais[message_count]);
}

/**	
 *  @brief send an ais message from socket to GNURadio
 *  @param message to be sent
 *  @return success/fail
 */
int sendmessage(string message){   
    int sock = socket_init(PORT_SEND); 
    message = message + '\0';
    send(sock , message.c_str(), message.length(), 0 ); 
    printf("Message sent\n"); 
    close(sock);
    return 0; 
}

/**	
 *  @brief send an ais certificate over socket to AIS GNURadio flowgraph
 *  @param Ship a struct storing Ship whose data has to be sent
 *  @param Ship_2 a struct storing Ship which will receive data from Ship
 *  @param CApublic public key of Certificate Authorty
 *  @param fd1 file descriptor of read socket
 *  @return success is 0 /fail
 */
int send_ais_certificate(ship_state_t *Ship, ship_state_t *Ship_2, octet* CApublic, int fd1){
    auto start = std::chrono::high_resolution_clock::now();
    //Generation of random number for nonce
    std::random_device seed_gen{};
    std::mt19937_64 mt_rand(seed_gen());
    Ship->nonce = {std::bitset<64>(mt_rand()).to_string()}; //to binary
    //Initialize and store certificate in char_certificate
    char char_certificate[2 * Ship->ECQVCert.len + 1]={'\0'};
    OCT_toHex(&Ship->ECQVCert, char_certificate);

    //First add certificate to payload
    // std::cout<<"\n char_certificate ="<<string(char_certificate)<<endl;
    string payload = hextobin(string(char_certificate));
    //DEBUG std::cout<<"Payload length ="<< payload.length()<<endl<<"Payload=\n"<<string(char_certificate)<<endl;
   
    //Remove last 32 bits as they are same as src MMSI, will be concatenated by receiver
    payload.erase(payload.length()-32);
    //std::cout<<"Certifcate Payload length ="<< payload.length()/8<<endl<<"Certifcate Payload=\n"<<payload<<endl;
    //Then add nonce
    payload = Ship->nonce+payload;
    Ship->nonce = bintohex(Ship->nonce);
    //Add security level to the beginning of payload
    payload = std::bitset<8>(SECURITY_LEVEL).to_string() + payload;

    ais_message_t ais[MAX_ALLOWABLE_MESSAGES];
    
    int message_count=0;
    const int max_payload_size_bytes = MAX_SLOTS_DATA_SIZE;
    const int payload_size_bytes = payload.length()/8;//Ship->ECQVCert.len + Ship->nonce.length()/8;
    //DEBUG printf("\nSize of payload = %d\n", payload_size_bytes);

    const int number_of_messages = ceil(payload_size_bytes / (float) max_payload_size_bytes);
    //DEBUG printf("\n Number of messages to be send = %d\n", number_of_messages);

    int start_index = 0, end_index = 0;
    long long microseconds = std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::high_resolution_clock::now() - start).count();
    test2_write_message("Preprocessing of SecureAIS exchange message(nonce,certificate) before transmitting", microseconds);
    
    //check size of payload, fit in 3 slots, max size allowed in 3 slots = 62 bytes according to AIS standard
    for (int i=0; i<number_of_messages; i++){
        string message={'\0'};
        //Send multiple messages, Divide payload into different slot messages if size > 3 continous slots
        end_index = max_payload_size_bytes*(i+1)*8;
        if(end_index > payload.length() ){
            end_index = payload.length();
        }
      //DEBUG   std::cout<<"Payload length ="<< payload.length()<<endl<<"Payload=\n"<<payload<<endl;
      //DEBUG    std::cout<<"\nMessage #"<<i<<"Startindex "<< start_index <<" End index"<<end_index <<endl;
        string payload_2_send = payload.substr(start_index, end_index - start_index );
        //DEBUG std::cout<<"\nMessage "<<payload_2_send;
        message = encode_ais_message_6(123456789, 123456789, i, payload_2_send);
        
       //DEBUG std::cout<<"\nMessage #"<<i<<"Startindex "<< start_index <<" End index"<<end_index <<endl<<message<<"payload:"<<payload_2_send<<endl;
       
        start_index = end_index; 
        Ship->message_sent += message;

        auto start = std::chrono::high_resolution_clock::now();
        int res = sendmessage(message);
        if (res != 0)
        {
            printf("Message not sent over socket....Exiting!\n");
            return 0;
        }
        read_ais(fd1, ais, message_count);
        long long microseconds = std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::high_resolution_clock::now() - start).count();
        test2_write_message("Sending/Receiving SecureAIS (nonce,certificate) packet# "+to_string(i), microseconds);
        message_count++;
    }

   //DEBUG printf("\nsequence: %d", ais[0].d.sequence );
  //DEBUG printf("\nPayload: %s\n", ais[0].d.payload_buffer );
    start = std::chrono::high_resolution_clock::now();

    string received_cert = "";
    int src_mmsi;
    string security_level_bits;
    for (int i=0; i<number_of_messages; i++){
      //  cout<<"\n AIS message"<<ais[i].d.payload_buffer;
        if(i==0){
            src_mmsi = ais[i].d.src_mmsi;
            string char2string = string(ais[i].d.payload_buffer);
            //first 3 bits are security level
            security_level_bits = char2string.substr(0,8);
            //first 64 bits are nonce
            Ship_2->received_nonce = bintohex(char2string.substr(8, 64));
            //Rest is part of certificate
            received_cert += char2string.substr(72,  std::string::npos );
            //cout<<"\n AIS message"<<ais[i].d.payload_buffer;
        }else{
            received_cert += (string) ais[i].d.payload_buffer;
        }
        Ship_2->message_received += ais[i].d.message; 
    }
 
    int security_level = (int)( std::bitset<64>(security_level_bits).to_ulong() );

    if (security_level == 0)
        return 0;
    
    //DEBUG cout<<"Received certificate:"<<received_cert.length()<<endl;
     //First get certificate
    received_cert = bintohex(received_cert);
    microseconds = std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::high_resolution_clock::now() - start).count();
    test2_write_message("Preprocessing AIS cert packets to get complete certificate", microseconds);
    ///Second get pub.key, remove last 8 hex characters, are validity time
    //cout<<"Received certificate:"<<received_cert<<endl;
    start = std::chrono::high_resolution_clock::now();
    string received_pubkey = received_cert.substr(0, received_cert.length() - 8 );
    microseconds = std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::high_resolution_clock::now() - start).count();
    test2_write_message("Extraction of secret material from certificate to gen Public Key later", microseconds);
    //cout<<"Received certificate:"<<received_pubkey<<endl;
    
    //3.5 Certificate Public Key Extraction Process: Cert PK Extraction
    //QU = ePU + QCA .
    char PU_extract_size[2 * field_size_EFS + 1];
    octet PU_extract = {0, sizeof(PU_extract_size), PU_extract_size}; //This is PU

    //Join bytes till public key size
    auto start_Pk = std::chrono::high_resolution_clock::now();
    start = std::chrono::high_resolution_clock::now();
    
    OCT_fromHex(&Ship_2->recvd_cert, (char *) received_cert.data());
    OCT_jint(&Ship_2->recvd_cert, src_mmsi, sizeof(src_mmsi));//32
    BIG e={0};
    Hn(&Ship_2->recvd_cert, e);
    
    microseconds = std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::high_resolution_clock::now() - start).count();
    test2_write_message("Addition of Src MMSI to cert and Hash operation to get e", microseconds);

    OCT_fromHex(&PU_extract, (char *) received_pubkey.data());
    
    //printf("Received cert extract: \n");
    //OCT_output(&Ship_2->recvd_cert);
    ECP QCA, QU, ECP_PU_extract;
    int res = ECP_fromOctet(&QCA, CApublic);
    if (res != 1)
    {
        printf("ECP from octet is invalid!\n");
        return 0;
    }
    ECP_fromOctet(&ECP_PU_extract, &PU_extract);
    //printf("\nECP_PU_extract!\n");
    //ECP_output(&ECP_PU_extract);
    start = std::chrono::high_resolution_clock::now();
    ECP_copy(&QU, &ECP_PU_extract);
    ECP_mul(&QU, e);
    microseconds = std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::high_resolution_clock::now() - start).count();
    test2_write_message("Compute H(Pa ,Ia )Pa", microseconds);

    start = std::chrono::high_resolution_clock::now();
    ECP_add(&QU, &QCA);
    microseconds = std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::high_resolution_clock::now() - start).count();
    test2_write_message("C + H(Pa ,Ia ) Pa", microseconds);

    ECP_toOctet(&Ship_2->recvd_public_key, &QU, false);

    res = ECP_PUBLIC_KEY_VALIDATE(&Ship_2->recvd_public_key);
    if (res != 0)
    {
        printf("ECP Public Key is invalid!\n");
        return res;
    }
    microseconds = std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::high_resolution_clock::now() - start_Pk).count();
    test2_write_message("Total time to Compute Pk", microseconds);

  //  printf("\nReceived ECP Public Key is:\n");
  //  OCT_output(&Ship_2->recvd_public_key);

    return 0;
}


/**
 * 	@brief Send AIS Tag function
 *  @param Ship Ship 1 data
 *  @param Ship_2 Ship 2 data
 *  @param type describe whether Ship 1 is transmitter = 1 or receiver = 2
 *  @param fd1 file descriptor of read socket
 */
int send_ais_auth_tag(ship_state_t *Ship, ship_state_t *Ship_2, int type, int fd1){
    
    auto start = std::chrono::high_resolution_clock::now();
    if (SECURITY_LEVEL != 0){
        //Complete Auth tag will be stored
        char auth_tag_message_size[5 * field_size_EFS + 1];
        octet auth_tag_message = {0, sizeof(auth_tag_message_size), auth_tag_message_size};

        if(type == 1){
            //if transmitter then sent data comes first
            OCT_jstring(&auth_tag_message, (char *)Ship->message_sent.data() );       
            OCT_jstring(&auth_tag_message, (char *)Ship->message_received.data());

        }else{
            //if receiver then received data comes first
            OCT_jstring(&auth_tag_message, (char *)Ship->message_received.data());
            OCT_jstring(&auth_tag_message, (char *)Ship->message_sent.data() );       
            
        }
        //generate 256 bit Auth tag using HMAC
        HMAC(MC_SHA2, SHA256, &Ship->auth_tag, SHA256, &Ship->session_key, &auth_tag_message);
    }else{
        OCT_fromHex(&Ship->auth_tag, (char *) "2028b65a7d8cb1a51745067e63ae9eee7e1bc4b52fc6680c7ac126414109c570" ); 
        OCT_fromHex(&Ship_2->auth_tag, (char *) "2028b65a7d8cb1a51745067e63ae9eee7e1bc4b52fc6680c7ac126414109c570" ); 
    }
    printf("\nAuth tag HMAC: ");
    OCT_output(&Ship->auth_tag);
    long long microseconds = std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::high_resolution_clock::now() - start).count();
    test2_write_message("Generation of Auth tag using HMAC function", microseconds);

    start = std::chrono::high_resolution_clock::now();
    //Change Octet to char for transmission
    char char_payload[Ship->auth_tag.len*2 + 1]={'\0'};
    OCT_toHex(&Ship->auth_tag, char_payload);

    string payload = string(char_payload);
    cout<<"\n auth_tag Payload = "<<payload<<endl;
    payload = hextobin(payload);

    //check size of payload, fit in 3 slots, max size allowed in 3 slots = 62 bytes according to AIS standard
    ais_message_t ais[MAX_ALLOWABLE_MESSAGES];
    int message_count=0;
    int max_payload_size_bytes = MAX_SLOTS_DATA_SIZE;
    int payload_size_bytes = Ship->auth_tag.len;
    //DEBUG printf("\nSize of payload = %d\n", payload_size_bytes);

    int counter = ceil(payload_size_bytes / (float) max_payload_size_bytes);
    //DEBUG printf("\nNumber of messages to be send = %d\n", counter);

    int start_index = 0, end_index = 0;
    //std::cout<<"Payload length ="<< payload.length()<<endl<<"Payload=\n"<<payload<<endl;
    microseconds = std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::high_resolution_clock::now() - start).count();
    test2_write_message("Preprocessing of SecureAIS auth tag before transmitting", microseconds);

    for (int i=0; i<counter; i++){
        //Send multiple messages, Divide payload into different slot messages if size > 3 continous slots
        end_index = max_payload_size_bytes*(i+1)*8;
        if(end_index > payload.length() ){
            end_index = payload.length();
        }
      //DEBUG   std::cout<<"Payload length ="<< payload.length()<<endl<<"Payload=\n"<<payload<<endl;
      //DEBUG std::cout<<"\nMessage #"<<i<<"Startindex "<< start_index <<" End index"<<end_index <<endl;
        string payload_2_send = payload.substr(start_index, end_index - start_index );
        string message = encode_ais_message_6(123456789,123456789, i, payload_2_send);
     //DEBUG   std::cout<<"\nMessage #"<<i<<"Startindex "<< start_index <<" End index"<<end_index<<endl<<message<<"\npayload:"<<payload_2_send<<endl;
        start_index = end_index; 
        auto start = std::chrono::high_resolution_clock::now();
        int res = sendmessage(message);
        if (res != 0)
        {
            printf("Message not sent over socket....Exiting!\n");
            return res;
        }
      
        start = std::chrono::high_resolution_clock::now();
        read_ais(fd1, ais, message_count);
        long long microseconds = std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::high_resolution_clock::now() - start).count();
        test2_write_message("Sending/Receiving of auth tag packet#"+to_string(i), microseconds);

        message_count++;
    }

   //DEBUG printf("\nsequence: %d", ais[0].d.sequence );
  //DEBUG printf("\nAIS Payload: %s\n", ais[0].d.payload_buffer );

    string received_auth_tag = "";
    for (int i=0; i<message_count; i++){
            received_auth_tag += (string) ais[i].d.payload_buffer;
    }
  //DEBUG  cout<<"\nReceived received_auth_tag:"<<received_auth_tag<<endl;
    received_auth_tag = bintohex(received_auth_tag);

     cout<<"\n Received received_auth_tag:"<<received_auth_tag<<endl;

    OCT_fromHex(&Ship_2->rcvd_auth_tag, (char *)received_auth_tag.data() );
    microseconds = std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::high_resolution_clock::now() - start).count();
    test2_write_message("Complete time for preprocessing/sending/receiving auth tag ", microseconds);

    return 0;
}

int Secure_AIS_protocol(csprng *RNG, int fd1, bool generate_keys = GEN_KEYS)
{

    int res, MMSI = 123456789;
    //Variables to store Public/private keys of certificate authority
    char cPr0[field_size_EGS], cPb0[2 * field_size_EFS + 1];
    octet CAprivate = {0, sizeof(cPr0), cPr0};
    octet CApublic = {0, sizeof(cPb0), cPb0};

    //Variables to store ship data
    ship_state_t Ship_1, Ship_2;    
    if (generate_keys){
        printf("\nGenerating keys\n");
        //Generation of Random keys for Certificate Authority
        ECP_KEY_PAIR_GENERATE(RNG, &CAprivate, &CApublic);
        res = ECP_PUBLIC_KEY_VALIDATE(&CApublic);
        if (res != 0)
        {
            printf("ECP Public Key is invalid!\n");
            return 0;
        }
       
        printf("\nCertificate Authority private key= 0x");
        OCT_output(&CAprivate);
        printf("Certificate Authority public key= 0x");
        OCT_output(&CApublic);
        
        //Generation of Random keys for Ship 1
        ECP_KEY_PAIR_GENERATE(RNG, &Ship_1.private_key, &Ship_1.public_key);
        res = ECP_PUBLIC_KEY_VALIDATE(&Ship_1.public_key);
        if (res != 0)
        {
            printf("ECP Public Key is invalid!\n");
            return res;
        }
    
        //Generation of ECQV certificate for Ship 1
        res = genECQVCert(RNG, &Ship_1, &CAprivate, &CApublic, MMSI);
        if (res != 0)
        {
            printf("ECQV certificate is invalid!\n");
            return res;
        }
        printf("\nCertificate of Ship 1: ");
        OCT_output(&Ship_1.ECQVCert);

        printf("\nPrivate key data oct Ship 1: ");
        OCT_output(&Ship_1.r_private_key);

        //Generation of Random keys for ship 2
        ECP_KEY_PAIR_GENERATE(RNG, &Ship_2.private_key, &Ship_2.public_key);
        res = ECP_PUBLIC_KEY_VALIDATE(&Ship_2.public_key);
        if (res != 0)
        {
            printf("ECP Public Key is invalid!\n");
            return 0;
        }
        //Generation of ECQV certificate for Ship 2
        res = genECQVCert(RNG, &Ship_2, &CAprivate, &CApublic, MMSI);
        if (res != 0)
        {
            printf("ECQV certificate is invalid!\n");
            return -1;
        }

        printf("\nCertificate of Ship 2: ");
        OCT_output(&Ship_2.ECQVCert);

        printf("\nPrivate key data oct Ship 2: ");
        OCT_output(&Ship_2.r_private_key);

    }else{
        printf("\n Using precompute keys\n");
        //Using precompute keys
        precompute_key_data_t key_pairs;
        setup_keys(key_pairs);
        //keys for Certificate Authority
        OCT_fromHex(&CAprivate, key_pairs.CAprivate );
        OCT_fromHex(&CApublic,  key_pairs.CApublic  );

        //keys for Ship 1
        OCT_fromHex(&Ship_1.ECQVCert,       key_pairs.Ship_1_ECQVCert );    
        OCT_fromHex(&Ship_1.r_private_key,  key_pairs.Ship_1_r_private_key );

        // keys for Ship 2
        OCT_fromHex(&Ship_2.ECQVCert,       key_pairs.Ship_2_ECQVCert );    
        OCT_fromHex(&Ship_2.r_private_key,  key_pairs.Ship_2_r_private_key ); 
    }

    
    auto start = std::chrono::high_resolution_clock::now();
    //Send ECQV certificate over the wire
    send_ais_certificate(&Ship_1, &Ship_2, &CApublic, fd1);
    long long microseconds = std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::high_resolution_clock::now() - start).count();
    test2_write_message("Total time for first protocol exchange from Ship 1 to Ship 2", microseconds);

    printf("Certificate of Ship1 received by Ship 2: \n");
    OCT_output(&Ship_2.recvd_cert);

    printf("Public key extract by Ship2 received from Ship 1 : \n");
    OCT_output(&Ship_2.recvd_public_key);

    //Do same thing for ship 2
    printf("\nShip 2 starting process\n");

   //Send ECQV certificate over the wire
    printf("\nSending ECQV Ship 2\n");
    start = std::chrono::high_resolution_clock::now();
    send_ais_certificate(&Ship_2, &Ship_1, &CApublic, fd1);
    microseconds = std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::high_resolution_clock::now() - start).count();
    test2_write_message("Total time for second protocol exchange from Ship 2 to Ship 1", microseconds);

    printf("Public key extract by Ship1 received from Ship 2: \n");
    OCT_output(&Ship_1.recvd_public_key);

    if(SECURITY_LEVEL != 0){
        // Calculate common key using DH - IEEE 1363 method
        auto start = std::chrono::high_resolution_clock::now();
        ECP_SVDP_DH(&Ship_1.r_private_key, &Ship_1.recvd_public_key, &Ship_1.DH_shared_key);
        long long microseconds = std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::high_resolution_clock::now() - start).count();
        test2_write_message("Generation of DH key on Ship 1", microseconds);

        start = std::chrono::high_resolution_clock::now();
        ECP_SVDP_DH(&Ship_2.r_private_key, &Ship_2.recvd_public_key, &Ship_2.DH_shared_key);
        microseconds = std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::high_resolution_clock::now() - start).count();
        test2_write_message("Generation of DH key on Ship 2", microseconds);

        printf("\n DH Ship 1: ");
        OCT_output(&Ship_1.DH_shared_key);
        printf("\n DH Ship 2: ");
        OCT_output(&Ship_2.DH_shared_key);

        if (!OCT_comp(&Ship_1.DH_shared_key, &Ship_2.DH_shared_key))
        {
            printf("*** ECPSVDP-DH Failed\n");
            return -1;
        }

        //Generate preliminary session key
        start = std::chrono::high_resolution_clock::now();
        KDF2(MC_SHA2, SHA256, &Ship_1.session_key, AESKEY, &Ship_1.DH_shared_key, NULL);
        microseconds = std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::high_resolution_clock::now() - start).count();
        test2_write_message("Generation of preliminary session key on Ship 1", microseconds);

        start = std::chrono::high_resolution_clock::now();
        KDF2(MC_SHA2, SHA256, &Ship_2.session_key, AESKEY, &Ship_2.DH_shared_key, NULL);
        microseconds = std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::high_resolution_clock::now() - start).count();
        test2_write_message("Generation of preliminary session key on Ship 2", microseconds);


        printf("\nShip 1's preliminary session Key=  0x");
        OCT_output(&Ship_1.session_key);
        printf("\nShip 2's preliminary session Key=  0x");
        OCT_output(&Ship_2.session_key);
    }
    //Auth tag
    printf("\nShip 1 Sending AIS Auth tag");
    send_ais_auth_tag(&Ship_1, &Ship_2, 1, fd1);
    printf("\nShip 2 Sending AIS Auth tag");
    send_ais_auth_tag(&Ship_2, &Ship_1, 2, fd1);

    if(SECURITY_LEVEL != 0){

        auto start = std::chrono::high_resolution_clock::now();
        if (!OCT_comp(&Ship_1.rcvd_auth_tag, &Ship_2.rcvd_auth_tag))
        {
            printf("*** Auth tag exchanged Failed\n");
            return -1;
        }
        long long microseconds = std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::high_resolution_clock::now() - start).count();
        test2_write_message("Verify auth tag", microseconds);

        //Generate link session key
        start = std::chrono::high_resolution_clock::now();
        OCT_jstring(&Ship_1.session_key, (char *)Ship_1.nonce.data() ); 
        OCT_jstring(&Ship_1.session_key, (char *)Ship_1.received_nonce.data() ); 
        KDF2(MC_SHA2, SHA256, &Ship_1.l_session_key, AESKEY, &Ship_1.session_key, NULL);
        microseconds = std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::high_resolution_clock::now() - start).count();
        test2_write_message("Generation of link session key on Ship 1", microseconds);
       
        start = std::chrono::high_resolution_clock::now();
        OCT_jstring(&Ship_2.session_key, (char *)Ship_2.received_nonce.data() ); 
        OCT_jstring(&Ship_2.session_key, (char *)Ship_2.nonce.data() ); 
        KDF2(MC_SHA2, SHA256, &Ship_2.l_session_key, AESKEY, &Ship_2.session_key, NULL);
        microseconds = std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::high_resolution_clock::now() - start).count();
        test2_write_message("Generation of link session key on Ship 2", microseconds);
       
        if (!OCT_comp(&Ship_1.l_session_key, &Ship_2.l_session_key))
        {
            printf("*** Failed: Link session key generation do not match!\n");
            return -1;
        }

        printf("\nShip 1's Link Key=  0x");
        OCT_output(&Ship_1.l_session_key);
        printf("\nShip 2's Link Key=  0x");
        OCT_output(&Ship_2.l_session_key);
    }
    
    return 0;
}

void test1(csprng *RNG, int fd1){
    //Test1 is getting 10 readings for each security level
    int i=0, number_of_reps = 10;
    ofstream outfile;
    outfile.open("test_1.csv", ios::out | ios::app );
    while( i<number_of_reps ){
            auto start = std::chrono::high_resolution_clock::now();
            int res = Secure_AIS_protocol(RNG, fd1);
            if (res != 0){
                //Failed, try again
                continue;
            }
            auto elapsed = std::chrono::high_resolution_clock::now() - start;
            long long microseconds = std::chrono::duration_cast<std::chrono::microseconds>(elapsed).count();
            printf("\nTime taken for exchange: %lld microseconds\n\n",  microseconds);

            if(i==0){

                string header="";
                if (SECURITY_LEVEL == 0)
                    header="No security";
                else if (SECURITY_LEVEL == 1)
                     header="80 bits";
                else if (SECURITY_LEVEL == 2)
                     header="128 bits";
                else if (SECURITY_LEVEL == 3)
                     header="192 bits";
                else if (SECURITY_LEVEL == 4)
                     header="256 bits";
                outfile << header << ", ";
            }
            // write inputted data into the file.
            if (i!=(number_of_reps-1)){
                outfile << microseconds << ", ";
            }else{
                outfile << microseconds << endl;
            }
            
            i++;
            sleep(1);
    }
    // close the opened file.
    outfile.close();
}

int main()
{
    int i,fd1;
    unsigned long ran;
   
    time((time_t *)&ran);
    char raw[100];
    octet RAW = {0, sizeof(raw), raw};
    csprng RNG;                // Crypto Strong RNG

    RAW.len = 100;              // fake random seed source
    RAW.val[0] = ran;
    RAW.val[1] = ran >> 8;
    RAW.val[2] = ran >> 16;
    RAW.val[3] = ran >> 24;
    for (i = 4; i < 100; i++) RAW.val[i] = i;

    CREATE_CSPRNG(&RNG, &RAW);  // initialise strong RNG

    printf("\nStarting SecureAIS protocol \n");

    do {
        sleep(1);
        fd1 = socket_init(PORT_RECEIVE);
    }while(fd1 == -1);
    printf("Connected to receive socket!\n");
    
    if(TEST==1 ){
        test1(&RNG, fd1);
    }
    else{
        auto start = std::chrono::high_resolution_clock::now();
        Secure_AIS_protocol(&RNG, fd1);
        auto elapsed = std::chrono::high_resolution_clock::now() - start;
        long long microseconds = std::chrono::duration_cast<std::chrono::microseconds>(elapsed).count();
        printf("\nTime taken for exchange: %lld microseconds\n\n",  microseconds);
        test2_write_message("Total time taken by protocol for exchange", microseconds);
    }

    KILL_CSPRNG(&RNG);
}

