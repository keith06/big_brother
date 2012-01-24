Big Brother activity monitor (= keyloger + stuff)
=================================================

Keylogger
---------

This is an advanced keylogger for Windows, created with the goal of monitoring students and preventing cheating during tests in the computer labs. It has no GUI, but it does show up in the process list. Features:

* log all keypresses, including combined ones (e.g. Ctrl-C and Ctrl-V)
* log all mouse clicks
* log the process name and title of the active window each time it is changed 
* monitor all files fitting a file mask and create their snapshots at regular intervals (this was intended to detect students who "miraculously" wrote most of their solution in a minute)
* upload all logs and monitored-file snapshots to a server via HTTP at regular intervals

Log inspector
-------------
 
The project also includes a minimal HTTP server that

* listens for incoming logs from keyloggers, parses them, stores them in a sqlite DB
* has a web interface for displaying the log in a human-readable way (including links to file snapshots)

Directory structure
-------------------

`BigBrother` contains the keylogger, written in C++.

`server` contains the HTTP server, written in python. In a single file. Don't judge :)

`stuff_unused` is just that - unused bits of code that might come handy with this or a related project, but are not used in BigBrother itself.
