Code and description for observing and modifying the Cloud communication of a [Radiothermostat CT-50 V1.94 WIFI connected thermostat](http://www.radiothermostat.com/wifi/).

# Background

The Radiothermostat CT-50, and similar thermostats from this manufacturer, have a well documented, completely unauthenticated JSON interface running on the thermostat's web server. There is some python code [here](https://github.com/mhrivnak/radiotherm) and [there](https://github.com/brannondorsey/radio-thermostat) that allows you to play with this interface. We're *not* interested in the thermostat's web server, but in the cloud function of this thermostat which, as far as I know, nobody looked at. 

The cloud function, when enabled, will call home every 300 seconds or so by posting to a configurable URL. A simple wireshark shows that this communication is over HTTP, but it's not in plaintext, except for a single header. I was curious to understand what data is passed through this connection, so I reverse engineered a thermostat firmware image that I stumbled upon, to find out. The script in this repo allows you to observe and modify the encrypted/authenticated messages in transit to and from the cloud backend.

# Thermostat crypto

The thermostat has a unique 12-character identifier, or "UUID". When you first provision your thermostat with the backend, you pass this UUID to the server through a webpage and it returns to you an 8-character string "authkey" which you fill into a webform on the thermostat. 

The "authkey" and "UUID" are used to derive an encryption key. The encryption key is derived by running a 1000 iterations of HMACSHA1. 

The "authkey" is then also used (without "UUID") to generate a MAC key. The MAC key is simply HMACMD5 over "authkey". 

The thermostat creates a different IV for each post to the cloud server and encrypts the message authentication code and the message itself with AES128-CBC. The cloud server responds in the same form using the same IV. Messages exchanged between thermostat and backend are thus encrypted and authenticated with two keys derived from "UUID" and "authkey".

Even though "authkey" is an 8-character string, I've only seen the cloud server return hex-strings during provisioning. So effectively the "authkey" is a 32-bit secret, and this is effectively the only secret from which the encryption and MAC keys are derived. These keys do not change until you re-provision the thermostat with a different "authkey". Not very strong no, but then again, this is no crypto wallet. 

# Extract the UUID from your thermostat

Visit "http://192.168.0.11/sys" in a browser (192.168.0.11 is where my thermostat is). This will return a JSON structure like this:

    {
      "uuid": "cee5bdefaced",
      "api_version": 113,
      "fw_version": "1.04.84",
      "wlan_fw_version": "v10.105576"
    }
What you need is in "uuid".

# Extract the authkey and server URL from your thermostat

Visit "http://192.168.0.11/cloud". This will return a JSON structure like this:


    {
      "interval": 300,
      "url": "http://ws.radiothermostat.com/services.svc/StatIn",
      "status": 1,
      "enabled": 1,
      "authkey": "11223344",
      "status_code": 200
    }

What you need is in "authkey" and "url".

# Run the sniffer in forward mode

Update: It seems Radiothermostat killed its cloud API, so we can't forward messages. Run the sniffer without -f to simply see the requests from the thermostat.


    ./thermosniff.py -p 8080 -f http://ws.radiothermostat.com/services.svc/StatIn cee5bdefaced 11223344 


This will start an HTTP server on port 8080; make sure there's firewall access to this port from the thermostat. You need to tell the thermostat to do its posts to this server now instead of the cloud backend. To do this, you can use curl (192.168.0.10 is where my thermosniff instance runs, 192.168.0.11 is where my thermostat is):

    curl -d '{"url":"http://192.168.0.10:8080"}' http://192.168.0.11/cloud
    curl -d '{"enabled": 0}' http://192.168.0.11/cloud
    curl -d '{"enabled": 1}' http://192.168.0.11/cloud


Now, after some time, you should see POSTs coming in to your server as follows. The encrypted and authenticated messages from the thermostat are JSON objects. The server also responds with encrypted and authenticated JSON objects.

The thermostat performs a normal post of the temperature stats, and the backend reponds with '{"ignore":0}', meaning "OK".

    [thermostat to us] => {"main_header":{"uuid":"cee5bdefaced","api_version":113,"fw_version":"1.04.84","epoch":23,"sequence":8949},"diagnostics":{},"tstat":{"temp":67.50,"tmode":1,"fmode":0,"override":1,"hold":0,"t_heat":66.50,"tstate":0,"fstate":0,"time":{"day":6,"hour":13,"minute":20},"t_type_post":0}}
    [us to thermostat] <= {"ignore":0}
    192.168.0.11 - - [16/Dec/2018 13:20:43] "POST / HTTP/1.1" 200 -

5 minutes later, a normal post from the thermostat, and the backend asks to set the target temp to 68 Fahrenheit.

    [thermostat to us] => {"main_header":{"uuid":"cee5bdefaced","api_version":113,"fw_version":"1.04.84","epoch":23,"sequence":8950},"diagnostics":{},"tstat":{"temp":67.50,"tmode":1,"fmode":0,"override":1,"hold":0,"t_heat":66.50,"tstate":0,"fstate":0,"time":{"day":6,"hour":13,"minute":25},"t_type_post":0}}
    [us to thermostat] <= {"t_heat":68.0}
    192.168.0.11 - - [16/Dec/2018 13:25:45] "POST / HTTP/1.1" 200 -

Another normal temp stats post, and an OK from the backend.

    [thermostat to us] => {"main_header":{"uuid":"cee5bdefaced","api_version":113,"fw_version":"1.04.84","epoch":23,"sequence":8951},"diagnostics":{},"tstat":{"temp":67.50,"tmode":1,"fmode":0,"override":1,"hold":0,"t_heat":68.00,"tstate":0,"fstate":0,"time":{"day":6,"hour":13,"minute":30},"t_type_post":0}}
    [us to thermostat] <= {"ignore":0}
    192.168.0.11 - - [16/Dec/2018 13:30:49] "POST / HTTP/1.1" 200 -

A normal temp stats post, and the backend asks to set the heating schedule. This thermostat supports a 7-day schedule of 5 zones per day.

    [thermostat to us] => {"main_header":{"uuid":"cee5bdefaced","api_version":113,"fw_version":"1.04.84","epoch":23,"sequence":8952},"diagnostics":{},"tstat":{"temp":67.50,"tmode":1,"fmode":0,"override":1,"hold":0,"t_heat":68.00,"tstate":0,"fstate":0,"time":{"day":6,"hour":13,"minute":35},"t_type_post":0}}
    [us to thermostat] <= {"program":{"heat":{"0":[390,62.5,1200,61.0,1200,61.0,1200,61.0],"1":[390,62.5,1200,61.0,1200,61.0,1200,61.0],"2":[390,62.5,1200,61.0,1200,61.0,1200,61.0],"3":[390,62.5,1200,61.0,1200,61.0,1200,61.0],"4":[390,62.5,1200,61.0,1200,61.0,1200,61.0],"5":[540,62.5,1320,61.0,1320,61.0,1320,61.0],"6":[540,62.5,1320,61.0,1320,61.0,1320,61.0]}}}
    192.168.0.11 - - [16/Dec/2018 13:35:51] "POST / HTTP/1.1" 200 -

A normal post, followed the backend asking for the heating schedule that's now programmed into the thermostat. Presumably to verify if it's set correctly.

    [thermostat to us] => {"main_header":{"uuid":"cee5bdefaced","api_version":113,"fw_version":"1.04.84","epoch":23,"sequence":8953},"diagnostics":{},"tstat":{"temp":67.50,"tmode":1,"fmode":0,"override":0,"hold":0,"t_heat":62.50,"tstate":0,"fstate":0,"time":{"day":6,"hour":13,"minute":40},"t_type_post":0}}
    [us to thermostat] <= {"cloud_request":{"program":{"heat":1}}}
    192.168.0.11 - - [16/Dec/2018 13:40:57] "POST / HTTP/1.1" 200 -

The thermostat immediately does another post (8 seconds after the previous post) to respond to the backend request. The post looks different in that it doesn't have the usual temp stats, but the requested heat schedule instead. As a response, the backend asks to set the target heat to 70 Fahrenheit (it was a cold rainy day in Oakland).

    [thermostat to us] => {"main_header":{"uuid":"cee5bdefaced","api_version":113,"fw_version":"1.04.84","epoch":23,"sequence":8954},"cloud_request":1,"program":{"heat":{"0":[390,62.50,1200,61,1200,61,1200,61],"1":[390,62.50,1200,61,1200,61,1200,61],"2":[390,62.50,1200,61,1200,61,1200,61],"3":[390,62.50,1200,61,1200,61,1200,61],"4":[390,62.50,1200,61,1200,61,1200,61],"5":[540,62.50,1320,61,1320,61,1320,61],"6":[540,62.50,1320,61,1320,61,1320,61]}}}
    [us to thermostat] <= {"t_heat":70.0}
    192.168.0.11 - - [16/Dec/2018 13:41:04] "POST / HTTP/1.1" 200 -

A normal post and the backend asks for the eventlog.

    [thermostat to us] => {"main_header":{"uuid":"cee5bdefaced","api_version":113,"fw_version":"1.04.84","epoch":23,"sequence":8955},"diagnostics":{},"tstat":{"temp":67.50,"tmode":1,"fmode":0,"override":1,"hold":0,"t_heat":70.00,"tstate":1,"fstate":0,"time":{"day":6,"hour":13,"minute":45},"t_type_post":0}}
    [us to thermostat] <= {"cloud_request":{"eventlog":1}}
    192.168.0.11 - - [16/Dec/2018 13:46:07] "POST / HTTP/1.1" 200 -

The thermostat immediately posts the event log, which contains the last approx. 30 minutes of temperature data and humidity (but this thermostat doesn't support humidity). Backend simply returns OK.

    [thermostat to us] => {"main_header":{"uuid":"cee5bdefaced","api_version":113,"fw_version":"1.04.84","epoch":23,"sequence":8956},"cloud_request":1,"eventlog":[["hour","minute","relay","temp","humidity","ttemp"],[13,9,64,67.00,0,66],[13,15,64,67.00,0,66],[13,20,64,67.50,0,66],[13,25,64,67.50,0,66],[13,30,64,67.50,0,68],[13,35,64,67.50,0,68],[13,40,64,67.50,0,62],[13,40,65,67.50,0,70]]}
    [us to thermostat] <= {"ignore":0}
    192.168.0.11 - - [16/Dec/2018 13:46:11] "POST / HTTP/1.1" 200 -

A normal post, followed by a request from the backend to stroke the watchdog.

    [thermostat to us] => {"main_header":{"uuid":"cee5bdefaced","api_version":113,"fw_version":"1.04.84","epoch":23,"sequence":8957},"diagnostics":{},"tstat":{"temp":68.00,"tmode":1,"fmode":0,"override":1,"hold":0,"t_heat":70.00,"tstate":1,"fstate":0,"time":{"day":6,"hour":13,"minute":50},"t_type_post":0}}
    [us to thermostat] <= {"wd_strobe":1}
    192.168.0.11 - - [16/Dec/2018 13:51:15] "POST / HTTP/1.1" 200 -

A normal post followed by a request for the thermostat's datalog.

    [thermostat to us] => {"main_header":{"uuid":"cee5bdefaced","api_version":113,"fw_version":"1.04.84","epoch":23,"sequence":8958},"diagnostics":{},"tstat":{"temp":69.00,"tmode":1,"fmode":0,"override":1,"hold":0,"t_heat":70.00,"tstate":1,"fstate":0,"time":{"day":6,"hour":13,"minute":55},"t_type_post":0}}
    [us to thermostat] <= {"cloud_request":{"datalog":1}}
    192.168.0.11 - - [16/Dec/2018 13:56:17] "POST / HTTP/1.1" 200 -

The thermostat responds immediately with the datalog, which consists of the running times of the heater and cooling unit (I don't have a cooling unit connected) for the previous day, and the current day up to present time.

    [thermostat to us] => {"main_header":{"uuid":"cee5bdefaced","api_version":113,"fw_version":"1.04.84","epoch":23,"sequence":8959},"cloud_request":1,"datalog":{"today":{"heat_runtime":{"hour":0,"minute":27},"cool_runtime":{"hour":0,"minute":0}},"yesterday":{"heat_runtime":{"hour":0,"minute":50},"cool_runtime":{"hour":0,"minute":0}}}}
    [us to thermostat] <= {"ignore":0}
    192.168.0.11 - - [16/Dec/2018 13:56:18] "POST / HTTP/1.1" 200 -

If you want to restore the thermostat to post to its original backend, run the curl command line to restore the URL with the one you fetched before (in my case "http://ws.radiothermostat.com/services.svc/StatIn") as follows:

    curl -d '{"url":"http://ws.radiothermostat.com/services.svc/StatIn"}' http://192.168.0.11/cloud

# Run the sniffer in non-forward mode

This mode is different in that we don't forward the thermostat requests to the cloud server; we just respond (encrypted and authenticated) '{"ignore":"0"}' which tells the thermostat to not take any additional action. To do so, just omit the cloud url from the command line:

    ./thermosniff.py -p 8080 cee5bdefaced 11223344

This is useful if you want to use these scripts to build your own cloud server.

# More commands from backend to the thermostat

There's many more commands that the backend can give to your thermostat as a response to the thermostat's POST, besides the examples I discussed above, including ones for updating the firmware. If you leave the sniffer running for some time, and you play with settings of the thermostat through the Radiostat website, you'll see a lot of them. If you want to build your own backend based on these scripts, I'm happy to give you some more details on the syntax of these commands. Send me a ping.
