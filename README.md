# Slow Rate HTTP2 DoS PoC

PoC of five Slow Rate HTTP/2 DoS attacks seen in the following research paper:

[Nikhil Tripathi and Neminath Hubballi. Slow rate denial of service attacks against http/2 and detection. *Comput. Secur.*, 72(C):255–272, January 2018.](https://www.sciencedirect.com/science/article/pii/S0167404817301980)

The tool measures the connection waiting time at the web server for the specified attack payload.

### Prerequisites

You will need Python3 with the [Hyper-h2](https://python-hyper.org/h2/en/stable/index.html) dependency:

```
apt install python3 python3-pip
pip3 install h2
```

### Run

```
$ ./slowh2attacks.py -h
usage: slowh2attacks.py [-h] {1,2,3,4,5} target port

positional arguments:
  {1,2,3,4,5}  specify the attack number
  target       specify the hostname or IP of the target
  port         target port
```

### Debug

Instructions to capture the decrypted traffic can be found [here](https://sharkfesteurope.wireshark.org/assets/presentations17eu/15.pdf).
