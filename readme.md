# 2DES meet in the middle attack
---------------------------------

To perform the attack, you need python 3 (tested working on 3.6) and ensure that you have `pyDes` installed. You can do this by running 

`pip install -r requirements.py`


You should be able to get the keys by simply running `./mitm.py`. You can change the plain text and cipher text by editing the variables at the top of `mitm.py`. Once you have the keys, use an online tool such as [this](http://des.online-domain-tools.com/), make sure you use 'ECB' mode.
