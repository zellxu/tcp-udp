README

Name:   Xiang Xu
Email:  zellxu@gatech.edu

Class:      CS 3251
Section:    A
Date:       Feb 11, 2015
Title:      TCP and UDP Applications Programming

Files Submitted
1. UDPServer.java
2. UDPClient.java
3. TCPServer.java
4. TCPClient.java

Instruction on Compiling and Running the Program
* Requirement*
JVM
Any machines - Mac OS, Windows, Linux (Mac OS Prefered)

* Compiling *
javac UDPServer.java UDPClient.java
javac TCPServer.java TCPServer.java

* Running *
java UDPServer [-d] [port_number]
java UDPClient [-d] [host:port] [username] [password]
java TCPServer [-d] [port_number]
java TCPClient [-d] [host:port] [username] [password]

-d is optional
port number is optional

Currently Stored Username: user1 user2 user3 user4 user5
Currently Stored Password: pass1 pass2 pass3 pass4 pass5

Program Description:
* Connection to Server *
After connection to the server, send message "REQ" to initiate the authentication process.

* Message *
Both UDP and TCP follow the same message format.

===============================================================================
Client Side
 ---------------------------------------------------------------------
| Short Hand | Message Type     | Response                            |
|------------|------------------|-------------------------------------|
|   REQ      | Request          | xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx |
|   CHA      | Random String    | Send URH                            |
|   URH      | Username & Hash  | xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx |
|   AUT      | Authentication   | Determine Result                    |
 ---------------------------------------------------------------------
Server Side
----------------------------------------------------------------------
| Short Hand | Message Type     | Response                            |
|------------|------------------|-------------------------------------|
|   REQ      | Request          | Send Random String                  |
|   CHA      | Random String    | xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx |
|   URH      | Username & Hash  | Compare result, send Authentication |
|   AUT      | Authentication   | xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx |
 ---------------------------------------------------------------------
Message Format:
- REQUEST -
Index 0-2: Message Type (REQ)

- RANDOM STRING -
Index 0-2: Message Type (CHA)
Index 3-66: Random String

- USERNAME & HASH
Index 0-2: Message Type (URH)
Index 3:   Username length
Index 3-[3+Username length]: Username
Index [3+Username length]-[3+Username length + hash length]: Hash

- AUTHENTICATION -
Index 0-2: Message Type (AUT)
Index 3:   Result (0=Fail, 1=Succeed)
===============================================================================
The process of the exchange goes:
Client > Server: REQ
Server > Client: CHA<random string>
Client > Server: URH<username length as 1 hex number><username><MD5>
Server > Client: AUT<0 or 1>

Note <> are not inclued in the message.

The last message client receives is the AUT message and should use it to
determine authentication result.

MD5 is generated using Java's MessageDigest class.

TCP handles multiple users by creating Thread for each connection.
UDP handles multiple users by storing corresponding random string
in a hashtable with host:port keys

UDP timeout is handled by waiting 5 seconds while receiving and
re-send last packet up to 5 times before exiting with a timeout.



