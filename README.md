# Cybersecurity-Project-1

This is a JWKS server using a RESTful HTTP API running on C++. The server runs locally (127.0.0.1:8080). The server generates an RSA key pair, generates a JWT with a unique Key ID, and JWKS list of public keys. 

Original code provided in newServer.cpp.

To run the program, the provided compiled file `server.exe` can be run. The supplied black box test client `proj1_checker.exe` is also included to test the server. All tests were run in two seperate Terminal instances using `./server.exe` and `./proj1_checker.exe` commands respectively.

***NOTE: THIS IS NOT AN OFFICIAL PRODUCT. THIS IS AN UNTESTED PROTOTYPE PROJECT FOR CLASS. PLEASE DO NOT USE IN PROFESSIONAL OR PERSONAL CYBERSECURITY PROJECTS.***

## Results of JWKS Server

### Black Box Results
![alt text](https://media.discordapp.net/attachments/1154202485024620585/1154203056846671883/image.png?width=1440&height=477)
### Server Results
![alt text](https://media.discordapp.net/attachments/1154202485024620585/1154203117932519434/image.png?width=1440&height=495)
### Test Suite Coverage (newServer.cpp)
![alt text](https://cdn.discordapp.com/attachments/1154202485024620585/1154202974021750844/image.png)


## 3rd Party Libraries Used
nlohmann/json: https://github.com/nlohmann/json

OpenSSL: https://github.com/openssl/openssl

CPP-HTTPLIB: https://github.com/yhirose/cpp-httplib

JWT++: https://github.com/Thalhammer/jwt-cpp

