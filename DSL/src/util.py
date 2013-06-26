#!/usr/bin/env python

def find_list(target, query):
    query = tuple(query)
    for i in xrange(len(target)):
        if tuple(target[i:i+len(query)]) == query:
            yield i
            
def address_to_bytes(a, num_bytes=4):
    result = []
    
    assert type(a) == int
    assert a >= 0
    
    for _ in xrange(num_bytes):
        result += ['%0.2x' % (a % 256)]
        a = a / 256
    
    return result            
