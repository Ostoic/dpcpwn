# DPCPwn
This is a short exploit script I wrote to serve as a Proof of Concept for a command injection vulnerability I found in a certain model of Cisco router. The DPC3848VM DOCSIS 3.0 Gateway is a relatively old Cisco router, from around 2014. I've encountered this model of router masquerading as a "Technicolor" router.

![Peek 2021-01-19 20-14](https://user-images.githubusercontent.com/8475295/105113486-0bd2f880-5a93-11eb-916f-7f63fa963278.gif)

# Installation

```
git clone https://github.com/Ostoic/dpcpwn
cd dpcpwn
pip3 install -r requirements.txt
```

# Technicolor DPC3848VM DOCSIS 3.0 Gateway RCE vulnerability

Tested on firmware: dpc3800-v303r2042162-160620a

The ping function of the router management website does not properly sanitize user-controlled input. This can lead to remote code execution since it allows one to send arbitrary commands to be executed by the device.

In the picture below is the diagnostics page which is available to authenticated users. The "Ping Target IPv4" field has 4 input boxes which allows users to type numbers in each to form an ip address. 

![Diagnostics Page](https://user-images.githubusercontent.com/8475295/105084315-29d53480-5a64-11eb-993e-0be7cfc4b7d3.png)

After the ping test is finished running, the following is seen at the bottom of the page

![Screenshot from 2021-01-19 14-49-34](https://user-images.githubusercontent.com/8475295/105085304-900e8700-5a65-11eb-8e0e-088d357d9efe.png)

The post request for the ping function looks as follows

![Screenshot from 2021-01-19 14-51-49](https://user-images.githubusercontent.com/8475295/105085581-ee3b6a00-5a65-11eb-88e0-0829fec165e5.png)

Of note is the ping_dst parameter in the request body. What if one were to write an arbitrary command into that parameter?

![image](https://user-images.githubusercontent.com/8475295/105087210-280d7000-5a68-11eb-962b-b172cb519438.png)

We can reasonably guess that the ping_dst parameter is substituted into a shell command of the form "/bin/sh -c ping {ping_dst}", so if we craft our input carefully we can execute any command we like. An easy way to do this without knowing exactly what the shell command looks like is to use bash command substitution (see the backticks `).

![image](https://user-images.githubusercontent.com/8475295/105087707-e7622680-5a68-11eb-8614-f7f7977e194c.png)

# Severity
Since this exploit is neither difficult nor complex, it is possible this vulnerability has already been exploited in the wild. It is also easy to cross-compile for the DPC3848's CPU architecture, so botnet slaves can easily be made for this system. Also, since the web server is running as root on the device we also get root access to the whole machine, making it easy to intercept network traffic with tcpdump.
