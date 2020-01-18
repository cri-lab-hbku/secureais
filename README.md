# SecureAIS - Proof of Concept
A Proof of Concept using gnuradio and Ettus X310 SDRs on how to set up key exchange between two AIS transceivers for secure communication. Uses ECC which allows for different levels of security levels, currently supported security levels are none, 80, 128, 192 and 256 bits.

<p align="center">
     <img alt="ais_tranceiver_flowgraph" src="./images/ais_tranceiver_flowgraph.png" width="500">
</p>

# Why create this?
Nobody has done it in a way that is standard compliant or requires just a software update to make a security service work on AIS. In theory two friendly ships can implement all of this before leaving harbour, then communicate in secrecy and it would be still valid for years.

# How to use
This project has two parts, a C++ program and a flowgraph in gnuradio. To set them up: </br>
1- Install gnuradio software <br />
2- Install gr-aistx_with_input block to gnuradio, instructions inside block folder on how to compile and install, remember if you are using PyBOMBS to initialize your environment first. <br />
3- Open ais_transceiever.grc flowgraph in gnuradio.  <br />
4- Make sure ports 51999 and 5200 are free. <br />
5- Execute main or compile code from source     <br />

# How to compile code
To compile from source or use a different security level
add flag -DSECURITY_LEVEL=1 --> this could be chosen from 0-4 where 0 = no security level, 1 = 80, 2 = 128, 3 = 192 and 4 = 256 bits. <br />
Other flags include: <br />
    -DPORT_SEND or -DPORT_RECEIVE to set another port for send/receive sockets <br />
    -DGEN_KEYS = true or false to set whether to generate keys or not <br />
Using gcc compile command would be: <br />
```
    g++ -O2 main.cpp -DSECURITY_LEVEL=1 ./secure_ais_protocol.cpp ./ais_receiver/*.c core-master/cpp/core.a -o main
```

# Contributing
Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change.

# Developers
-Ahmed Aziz
-Pietro Tedeschi
-Savio Sciancalepore
-Roberto Di Pietro
Division of Information and Computing Technology (ICT)
College of Science and Engineering (CSE)
Hamad Bin Khalifa University (HBKU), Doha, Qatar
{aaziz, ptedeschi}@mail.hbku.edu.qa, {ssciancalepore, rdipietro}@hbku.edu.qa

# Credits
Credits go to the original authors of MIRACL core crypto library, gr_aistx and ais_receiver whose original efforts made this possible
<br />
https://github.com/miracl/core  <br />
https://github.com/trendmicro/ais   <br />
https://github.com/juan0fran/ais_rx <br />
