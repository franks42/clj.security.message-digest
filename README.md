# clj.security.message-digest

A functional clojure library for the creation of secure hashes, i.e. message digests, 
thru one-way functions like MD5, SHA-1, SHA-256, SHA-512, etc. 

(not sure about the practicality  - more an educational exercise in interface design...)

## Introduction

Under the covers, this library uses the "java.security.MessageDigest" library. However, instead of using the Java methods directly, a more clojuresque and functional abstraction is layered on top of the native mutable objects and state-changing methods. 
 
The "clj.security.message-digest" library works with immutable "message-digest" objects and with pure functional "update" and "digest" functions.

The "Usage" section is divided in three sections: the first section shows a functional interface usage that tries to mimic the equivalent non-functional java one. The second section shows some additional features that make the digesting operations easier on data structures. Lastly, by using message-digest objects as digester functions themselves, it brings the interfaces on yet another level of abstraction.

The "What's wrong with the Java interface?" at the end gives example of the java interface usage, and shows how the mutable objects and state-changing methods interact.

The end result is a clojure abstraction for secure hashing that improves on the java interface by providing an immutable digest-message object, where the update function returns a new updated digest-message object, while the digest function returns the secure hash value without changing the digest-message object: it gives you a pure functional interface for message digesting or secure hashing.

As icing on the cake, it also tries to deal with (unicode-)strings in a more friendly way, allows for an infinite number of arguments to update&digest, makes the message-digest usable as a function, and all can be used in higher-order functions.


## Installation

Something about versions, leiningen, clojars, and how to start a repl...

## Usage

### A functional java.security.MessageDigest-like approach

When you're familiar with the "java.security.MessageDigest" interfaces, then it will be easy to use the equivalent, more functional interface. Instead of "java.security.MessageDigest/getInstance" we have the "make-message-digest" factory function, which returns a "message-digest" instance. There are also the "update" and "digest" functions that do almost the same thing as the Java methods with the same name. The differences are that neither "update" nor "digest" changes the "message-digest" instance that it works on: the "message-digest" object is immutable. Therefor, the "update" function returns a new "message-digest" instance that incorporates the updated digest-accumulator, and the "digest" function does not reset the message-digest's accumulator but leaves it as is.

The following repl-examples should make the differences clear:

	user=> (require '(clj.security [message-digest :as md]))
	nil
	user=> (def my-initial-digest (md/make-message-digest "SHA-1"))
	#'user/my-initial-digest
	user=> (def my-updated-digest (md/update my-initial-digest (.getBytes "abc" "UTF-8")))
	#'user/my-updated-digest
	user=> (def my-final-abc-digest-value (md/digest my-updated-digest))
	#'user/my-final-abc-digest-value
	user=> my-final-abc-digest-value
	#<byte[] [B@6d392fa5>
	user=> (md/bytes2hex my-final-abc-digest-value)
	"A9993E364706816ABA3E25717850C26C9CD0D89D"

Note that the initial and updated digest objects are not changed:

	user=> (md/bytes2hex (md/digest my-initial-digest))
	"DA39A3EE5E6B4B0D3255BFEF95601890AFD80709"
	user=> (md/bytes2hex (md/digest my-updated-digest))
	"A9993E364706816ABA3E25717850C26C9CD0D89D"
	user=> (md/bytes2hex (md/digest (md/update my-initial-digest  (.getBytes "abc" "UTF-8"))))
	"A9993E364706816ABA3E25717850C26C9CD0D89D"
	user=> (md/bytes2hex (md/digest my-initial-digest  (.getBytes "abc" "UTF-8")))
	"A9993E364706816ABA3E25717850C26C9CD0D89D"
	user=> (md/bytes2hex (md/digest (md/update my-initial-digest  (.getBytes "ab" "UTF-8")) (byte 99)))
	"A9993E364706816ABA3E25717850C26C9CD0D89D"

So... clj.security.message-digest provides an equivalent functional interface for java.security.MessageDigest - we could stop here..., but that would be a shame ;-)

### A more Clojuresque Message Digest Interface

There are few more features that make it easier to digest the strings and bytes of data structures like lists and trees. 
* First of all, both the "update" and "digest" functions support a variable number of arguments to digest. 
* Second, the byte encoding of strings and chars is done implicitly by specifying a charset as an argument. 
* Third, the "message-digest" instance is implicitly created inside of the "update" and "digest" function if one does not pass a "digest-message" object as the first argument. The digest-algorithm for this newly created digest-message instance can either be specified by a first keyword argument, or by using the "\*default-digest-algorithm\*" and "\*default-charset\*" dynamic variables.

Specify both digest-algorithm and charset as keyword values in the factory function, and show variable number of arguments of different types:

	user=> (md/bytes2hex (md/digest (md/update (md/make-message-digest :sha-1 :utf-8) "abc")))
	"A9993E364706816ABA3E25717850C26C9CD0D89D"
	user=> (md/bytes2hex (md/digest (md/update (md/make-message-digest :sha-1 :utf-8) "a" "b" "c")))
	"A9993E364706816ABA3E25717850C26C9CD0D89D"
	user=> (md/bytes2hex (md/digest (md/update (md/make-message-digest :sha-1 :utf-8) "a" \b (byte 99))))
	"A9993E364706816ABA3E25717850C26C9CD0D89D"
	user=> (md/bytes2hex (md/digest (md/make-message-digest :sha-1 :utf-8) "a" \b (byte 99)))
	"A9993E364706816ABA3E25717850C26C9CD0D89D"

Implicitly create a "message-digest" object inside of "update" and "digest" if needed:

	user=> (md/bytes2hex (md/digest (md/update :sha-1 :utf-8 "a" \b (byte 99))))
	"A9993E364706816ABA3E25717850C26C9CD0D89D"
	user=> (md/bytes2hex (md/digest  :sha-1 :utf-8 "a" \b (byte 99)))
	"A9993E364706816ABA3E25717850C26C9CD0D89D"
	user=> (md/bytes2hex (md/digest "a" \b (byte 99)))
	"A9993E364706816ABA3E25717850C26C9CD0D89D"
	user=> (binding [md/*default-digest-algorithm* :sha-1 md/*default-charset* :utf-8] (md/bytes2hex (md/digest  "a" \b (byte 99))))
	"A9993E364706816ABA3E25717850C26C9CD0D89D"
	user=> (binding [md/*default-digest-algorithm* :md5 md/*default-charset* :utf-8] (md/bytes2hex (md/digest  "a" \b (byte 99))))
	"900150983CD24FB0D6963F7D28E17F72"


### An even more Clojuresque Message Digest Interface

Conceptually and also implementation-wise, the "make-message-digest" and "update" functions are truly equivalent and the same in functionality: they both return a new "message-digest" instance from either an existing "message-digest" or by creating a new one if needed. If a new "message-digest" is needed, then the first parameter MUST indicate the digest-algorithm either thru a string or keyword. Any subsequent parameters are either those entities that have to be digested or a keyword-indicator for the charset of the subsequent string or chars to digest. The charset MUST be indicated with a keyword to distinguish it from the strings that are to be digested.

	user=> (md/bytes2hex (md/digest (md/update (md/update (md/update :sha-1 :utf-8 "a") \b) (byte 99))))
	"A9993E364706816ABA3E25717850C26C9CD0D89D"
	user=> (md/bytes2hex (md/digest (md/make-message-digest (md/make-message-digest (md/make-message-digest :sha-1 :utf-8 "a") \b) (byte 99))))
	"A9993E364706816ABA3E25717850C26C9CD0D89D"

In other words, the "make-message-digest" and "update" functions are interchangeable.

Furthermore, the "message-digest" instances themselves can also be used as functions, like:

	user=> (def my-initial-digester (md/make-message-digest :sha-1 :utf-8))
	#'user/my-initial-digester
	user=> (md/bytes2hex (md/digest (my-initial-digester "abc")))
	"A9993E364706816ABA3E25717850C26C9CD0D89D"

So a "message-digest" object can be seen as a "digester" function that has the accumulated digest baked in, and it will return a new "message-digest" object/digester which has the digests of the additional arguments added to the accumulator: it has the equivalent functionality of the "update" function.

Finally, if the "message-digest" object as a function is called without any arguments, it will return the final digest value of the accumulated digests itself:

	user=> (def my-initial-digester (md/make-message-digest :sha-1 :utf-8))
	#'user/my-initial-digester
	user=> (def my-final-digester (my-initial-digester "abc"))
	#'user/my-final-digester
	user=> (md/bytes2hex (my-final-digester))
	"A9993E364706816ABA3E25717850C26C9CD0D89D"
	user=> (md/bytes2hex ((my-initial-digester "abc")))
	"A9993E364706816ABA3E25717850C26C9CD0D89D"
	user=> (md/bytes2hex (((md/make-message-digest :sha-1 :utf-8) "abc")))
	"A9993E364706816ABA3E25717850C26C9CD0D89D"

In other words, the "message-digest" object as a function is equivalent to both the "update" and "digest" functions, which implies that only having the "make-message-digest" would suffice.

See "https://gist.github.com/franks42/5074268" for an additional example repl-session.

See "clj.security.message-digest-test" file for more examples.

(see "http://www.nsrl.nist.gov/testdata/")

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
	
As mentioned, accumulator is reset by digest method, so calling it again gives you the initial zero-bytes digest value!!! :
	
	user=> (bytes2hex (.digest d)) 
	"DA39A3EE5E6B4B0D3255BFEF95601890AFD80709"
	
The update method only accepts byte(s), so (unicode-)strings have to be transformed/encoded to bytes by specifying the charset:
	
	user=> (.update d (.getBytes "abc" "UTF-8"))
	nil
	user=> (bytes2hex (.digest d))
	"A9993E364706816ABA3E25717850C26C9CD0D89D"
	
If you need for example the digest value for both "a" and "abc", then in order to reuse the accumulated digest of "a", you have to clone the MessageDigest instance before the additional "bc" digesting because of the automatic reset by the digest method, like:
	
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

*	a DigestMessage instance is not immutable as it's changed in-place by the update and digest methods
	
*	the update method doesn't return anything, which makes chaining of calls impossible
	
*	the digest method automatically resets the DigestMessage accumulator

Note that the clone method does make a clean copy of the MessageDigest accumulator instance, and that functionality is used under the covers in this clojure library to provide the required immutability. 


## Continuous Integration

[![Build Status](https://travis-ci.org/franks42/clj.security.message-digest.png?branch=master)](http://travis-ci.org/franks42/clj.security.message-digest)

## License

Copyright © 2013 Frank Siebenlist

Distributed under the Eclipse Public License, the same as Clojure.
