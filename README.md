# ChatRoom

ChatRoom is having a chatServer application, which supports multi threading.
Upon running chatServer, it will give a "server prompt", where one can control the server.
A chatClient application has been added, which is having minimal graphical interface.

As security is one of the primary concern, application is designed
to encrypt messages with unique AES key for an unique user, which will
be sent to the particular user by encrypting it using RSA algorithm,
which ensures only the individual user has the unique asymmetric key.
It helps protecting MITM attacks.

# USAGE

To run server application:
./chatServer.py

NOTE: By default it stores the log file by default in /tmp directory

To run client application:
./chatClient.py [SERVER_IP]

NOTE: By default logging is disabled.