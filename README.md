# LMEM

This is lMem, a fast memory checking framework.
For a high-level description of the framework read
[Usenix ATC publication](http://nebelwelt.net/publications/files/13ATC.pdf),
or have a look at
[the presentation](http://nebelwelt.net/publications/files/13ATC-presentation.pdf).


To install just do make (see INSTALL).

To see how to use the C malloc wrapping library, see lMem/tp/wrap.c
To see how to use the C++ new wrapping library, see lMem/tp/new.cpp
These are two programs that access out of bounds memory and it is 
detected by lMem.
Run them as:
```
./lMem tp/new
./lMem tp/wrap
```
There is also a program that shows how to programmatically set
watchpoints.
```
./lMem tp/hits
```

See FILES for a description of what is where.

```
./test.sh ...runs a small test suite
make test ... runs unit tests
make documentation ...  to generate doxygen html docs
```

... and much more ...

Enjoy!
