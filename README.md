# clj.security.message-digest

A functional clojure library for the creation of secure hashes, i.e. message digests, 
thru the one-way functions known by the names of MD5, SHA-1, SHA-256, SHA-512, etc. 
Under the covers, the java.security.MessageDigest library is used.
The interfaces are functional as the message-digest object, which holds the accumulated
digest state, is immutable. The "message-digest" factory function creates a new 
message-digest object, and is passed the digest-algorithm to use for the hashing as well 
as the utf-encoding to use for strings. The "update" function returns a new updated 
message-digest object, while the "digest" function generates the accumulated digest 
without changing the passed message-digest object. 
The functional interfaces allow for a more clojuresque and worry-free coding experience.
Furthermore, as the update function returns a new immutable, updated message-digest object,
it can safely be used in higher-order reduce-like functions.
Lastly, both update and digest can be passed a variable number of arguments, 
which will be digested lazely to accommodate a virtual infinite number of args. Also,
the arguments can be a mix of strings, characters, bytes or byte-arrays that will be 
transparently utf-encoded if needed, and nils are ignored.

## Usage

	user=> (def d0 (message-digest "SHA-1" "UTF-8"))
	#'user/d0
	user=> (->hex (digest d0 "abc"))
	"A9993E364706816ABA3E25717850C26C9CD0D89D"
	user=> (->hex (digest (update d0 "abc")))
	"A9993E364706816ABA3E25717850C26C9CD0D89D"
	user=> (->hex (digest (update d0 (.getBytes "a" "UTF-8") \b (byte 99))))
	"A9993E364706816ABA3E25717850C26C9CD0D89D"
	user=> (->hex (apply digest d0 (repeat 1000000 "a")))
	"34AA973CD4C4DAA4F61EEB2BDBAD27316534016F"

(see "http://www.nsrl.nist.gov/testdata/")

See "clj.security.message-digest-test" file for more examples.


## What's wrong with the Java interface?

When you call digest on the message-digest accumulator, it returns the digest... and resets the accumulator!
So the next call will give you the digest value for zero bytes.

The update function updates the accumulator, but doesn't return anything. 
So you're unable to chain subsequent calls.
Although, that may be safer as java's message-digest object has been changed in-place...

The clone method does make a clean copy of the whole message-digest accumulator, and that functionality is used in the clojure shim to provide the illusion of immutability. Well... it's more than an illusion, the clojure interface gives you a pure functional interface for the message digesting. 




## License

Copyright © 2013 Frank Siebenlist

Distributed under the Eclipse Public License, the same as Clojure.
