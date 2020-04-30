# LazyCap

## What is LazyCap?
LazyCap is a tool for a lazy man-in-the-middle attack. It start by scanning
the local network for hosts.Then it starts an arp spoofing attack. Finally it
captures http packets from the host. If installed, sslstrip can be used to
capture https requests as well. 

Maybe in the future I might add the feature to use sslstrip in LazyCap as well.

## Installation
````
$ python3 setup.py install
````
or
````
$ pip install .
````

Be sure to run with ``python3``.
```
usage: lazycap.py [-h]

LazyCap is a tool for a lazy man-in-the-middle attack. It start by scanning
the local network for hosts.Then it starts an arp spoofing attack. Finally it
captures http packets from the host. If installed, sslstrip can be used to
capture https requests as well.

optional arguments:
  -h, --help  show this help message and exit

```
Just run using ``python3 lazycap.py`` and follow the prompts.

## License
LazyCap is released under the Apache 2.0 license. See [LICENSE](https://github.com/adadonder/LazyCap/blob/master/LICENSE) for details.


## Contact
Feel free to contact me via e-mail: adadonderr@gmail.com
