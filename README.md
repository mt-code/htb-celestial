# HTB Celestial

## About
Python script that automates a back-connect shell on the HackTheBox machine **Celestial**.

Exploits a NodeJS deserialisation vulnerability:
https://www.exploit-db.com/docs/english/41289-exploiting-node.js-deserialization-bug-for-remote-code-execution.pdf

## Requirements
Requires netcat to be installed on your system and installed to your $PATH as **nc**

## Usage
Specify the host and port you wish to listen on, along with the path to the malicious WAR shell.

`htb-celestial.py {LHOST} {LPORT}`