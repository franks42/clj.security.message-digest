# clj.security.message-digest

# !! STILL EARLY BETA... PLS STAY AWAY FROM THIS CODE FOR YOUR OWN GOOD !!

A functional clojure library for the creation of secure hashes, i.e. message digests, 
thru the one-way functions known by the names of MD5, SHA-1, SHA-256, SHA-512, etc. 
Under the covers, the java.security.MessageDigest library is used.
The interfaces are functional as the message-digest object, which holds the accumulated
digest state, is immutable. The "message-digest" factory function creates a new 
message-digest object, and is passed the digest-algorithm to use for the hashing as well 
as the charset/utf-encoding to use for strings. The "update" function returns a new updated 
message-digest object, while the "digest" function generates the accumulated digest 
without changing the passed message-digest object. 
The functional interfaces allow for a more clojuresque and worry-free coding experience.
Furthermore, as the update function returns a new immutable, updated message-digest object,
it can safely be used in higher-order reduce-like functions.
Lastly, both update and digest can be passed a variable number of arguments, 
which will be digested lazely to accommodate a virtual infinite number of args. Also,
the arguments can be a mix of strings, characters, bytes or byte-arrays that will be 
transparently charset/utf-encoded if needed, and nils are ignored.

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

See "https://gist.github.com/franks42/5074268" for example repl-session.

See "clj.security.message-digest-test" file for more examples.


## What's wrong with the Java interface?

Well... it's not exactly "functional" in its approach...

Some examples in the repl with the native java interface may drive that message home:

First get a MessageDigest object

	user=> (import 'java.security.MessageDigest)
	java.security.MessageDigest
	user=> (def d (java.security.MessageDigest/getInstance "SHA-1"))
	#'user/d
	user=> d
	#<Delegate SHA-1 Message Digest from SUN, <initialized>
	
The digest method generates and returns the accumulated final digest as a byte array.
Note that accumulator is reset by the digest function, but that is not visible as we're working with an initial, i.e. reset, MessageDigest
	
	user=> (.digest d)  ;; digest value of initial sha-1 accumulator
	#<byte[] [B@119e7782>
	user=> (bytes2hex (.digest d))  ;; hex'ing the bytes - note accumulator is reset!
	"DA39A3EE5E6B4B0D3255BFEF95601890AFD80709"
	
The update method adds the hash of the passed byte(s) to the accumulated digest. Note that update doesn't return anything:
	
	user=> (.update d (byte 97))  ;; updating the accumulator with the digest of a single byte
	nil
	user=> (.update d (byte 98))  ;; and another byte
	nil
	user=> (.update d (byte 99))  ;; and one more
	nil
	user=> (bytes2hex (.digest d))  ;; finally generate the final digest value for "abc"
	"A9993E364706816ABA3E25717850C26C9CD0D89D"
	
As mentioned, accumulator is reset by digest method!!! :
	
	user=> (bytes2hex (.digest d)) 
	"DA39A3EE5E6B4B0D3255BFEF95601890AFD80709"
	
The update method only accepts byte(s), so (unicode-)strings have to be transformed/encoded to bytes by specifying the charset:
	
	user=> (.update d (.getBytes "abc" "UTF-8"))
	nil
	user=> (bytes2hex (.digest d))
	"A9993E364706816ABA3E25717850C26C9CD0D89D"
	
If you need for example the digest value for both "a" and "abc", then in order to reuse the accumulated digest of "a", you have to clone the MessageDigest instance for the additional "bc" digesting because of the automatic reset by the digest method, like:
	
	user=> (.update d (.getBytes "a" "UTF-8"))
	nil
	user=> (def d-clone (.clone d))
	#'user/d-clone
	user=> (.update d-clone (.getBytes "bc" "UTF-8"))
	nil
	user=> (bytes2hex (.digest d))
	"86F7E437FAA5A7FCE15D1DDCB9EAEAEA377667B8"
	user=> (bytes2hex (.digest d-clone))
	"A9993E364706816ABA3E25717850C26C9CD0D89D"
	user=> (bytes2hex (.digest d))
	"DA39A3EE5E6B4B0D3255BFEF95601890AFD80709"
	user=> (bytes2hex (.digest d-clone))
	"DA39A3EE5E6B4B0D3255BFEF95601890AFD80709"

What this example session shows is that:

	a DigestMessage instance is not very immutable as it's changed in-place by the update and digest methods
	
	the update method doesn't return anything, which makes chaining of calls impossible
	
	the digest method automatically resets the DigestMessage accumulator

This clojure abstraction tries to improve on the java interface by providing an immutable digest-message object, where the update function returns a new updated digest-message object, and the digest function returns the secure hash value without changing the digest-message object.

The clone method does make a clean copy of the whole message-digest accumulator, and that functionality is used in the clojure shim to provide the illusion of immutability. Well... it's more than an illusion, the clojure interface gives you a pure functional interface for the message digesting. 


## License

Copyright © 2013 Frank Siebenlist

Distributed under the Eclipse Public License, the same as Clojure.
