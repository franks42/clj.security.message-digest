(ns clj.security.message-digest
  "A functional clojure library for the creation of secure hashes, i.e. message digests, 
  thru the one-way functions known by the names of MD5, SHA-1, SHA-256, SHA-512, etc. 
  Under the covers, the java.security.MessageDigest library is used.
  The interfaces are functional as the message-digest object, which holds the accumulated
  digest state, is immutable. The \"message-digest\" factory function creates a new 
  message-digest object, and is passed the digest-algorithm to use for the hashing as well 
  as the charset to use for strings. The \"update\" function returns a new updated 
  message-digest object, while the \"digest\" function generates the accumulated digest 
  without changing the passed message-digest object. 
  The functional interfaces allow for a more clojuresque and worry-free coding experience.
  Furthermore, as the update function returns a new immutable, updated message-digest object,
  it can safely be used in higher-order reduce-like functions.
  Lastly, both update and digest can be passed a variable number of arguments, 
  which will be digested lazely to accommodate a virtual infinite number of args. Also,
  the arguments can be a mix of strings, characters, bytes or byte-arrays that will be 
  transparently utf-encoded if needed, and nils are ignored.
  Example:
  user=> (def d0 (message-digest \"SHA-1\" \"UTF-8\"))
  #'user/d0
  user=> (->hex (digest d0 \"abc\"))
  \"A9993E364706816ABA3E25717850C26C9CD0D89D\"
  user=> (->hex (digest (update d0 \"abc\")))
  \"A9993E364706816ABA3E25717850C26C9CD0D89D\"
  user=> (->hex (digest (update d0 (.getBytes \"a\" \"UTF-8\") \\b (byte 99))))
  \"A9993E364706816ABA3E25717850C26C9CD0D89D\"
  user=> (->hex (apply digest d0 (repeat 1000000 \"a\")))
  \"34AA973CD4C4DAA4F61EEB2BDBAD27316534016F\"
  (see \"http://www.nsrl.nist.gov/testdata/\")
  "
  (:require [clojure.string])
  (:import [java.security.MessageDigest]
           [java.nio.charset.Charset]))

;; http://www.nsrl.nist.gov/testdata/

;; "http://www.w3.org/2000/09/xmldsig#sha1"
;; "http://www.w3.org/2001/04/xmlenc#sha256"
;; "http://www.w3.org/2001/04/xmlenc#sha512"


;; user=> (java.nio.charset.Charset/isSupported "utf-8")
;; true
;; user=> (java.nio.charset.Charset/isSupported "utf-88")
;; false
;; user=> (java.nio.charset.Charset/forName "utf-8")
;; #<UTF_8 UTF-8>
;; user=> (.name (java.nio.charset.Charset/forName "utf-8"))
;; "UTF-8"

(defn charset-name 
  "Returs the canonical charset name for s and throws exception when s does not refer to a valid charset."
  [s]
  (.name (java.nio.charset.Charset/forName s)))


(def ^:dynamic *default-digest-algorithm*
  "Dynamic var that holds the default digest-algorithm to use for the message digesting, i.e. secure hashing."
  "SHA-1")


(def ^:dynamic *default-charset* 
  "Dynamic var that holds the default charset to use to transform strings to 
  byte-arrays for the message digesting, i.e. secure hashing."
  (charset-name "UTF-8"))


(defn ->bytes
  "Transforms the input argument value to a byte-array.
  Uses specified charset for strings and chars when necessary.
  Input can be (vector-of :byte ...)
  Output can be used to feed message digesters"
  ([s] (->bytes *default-charset* s))
  ([charset s]
  (cond
    (char? s) (.getBytes (str s) charset)
    (string? s) (.getBytes s charset)
    (= (type s) clojure.core.Vec) (byte-array s)
    :else s)))

(deftype TMessageDigest [msg-digest charset])


(defn message-digest
  "Factory function to create TMessageDigest objects for use with \"update\" and \"digest\".
  digest-algo - string indicating the digest algorithm to use, like \"SHA-256\"
  charset - string indicating the text encoding to use, like \"UTF-8\"
  When no arguments are passed, the values of the dynamic vars 
  *default-digest-algorithm* and *default-charset* will be used.
  Returns a new TMessageDigest object."
  ([] 
    (TMessageDigest. 
      (java.security.MessageDigest/getInstance *default-digest-algorithm*)
      (charset-name (name *default-charset*))))
  ([digest-algo] 
    (let [digest-algo (clojure.string/upper-case (name digest-algo))
          digest (java.security.MessageDigest/getInstance digest-algo)]
      (TMessageDigest. 
        digest 
        (charset-name (name *default-charset*)))))
  ([digest-algo charset] 
    (let [digest-algo (clojure.string/upper-case (name digest-algo))
          digest (java.security.MessageDigest/getInstance digest-algo)
          charset (charset-name (name charset))]
      (TMessageDigest. digest charset)))
  ([digest digest-algo charset] 
    (let [digest-algo (.getAlgorithm digest)
          charset (charset-name (name charset))]
      (TMessageDigest. digest charset))))


(defprotocol IMessageDigest
  "Defines the -update and -digest interfaces for TMessageDigest objects."
    (-update [this bytes-or-str]
    "See \"update\" function")
    (-digest [this][this bytes-or-str] 
    "See \"digest\" function")
    (algorithm [this] 
    "Returns the message-digest/secure-hash algorithm name for this digester")
    (charset [this] 
    "Returns the configured charset name that will be used for string2bytes 
    encoding for this digester")
  )


(extend-type TMessageDigest
  IMessageDigest
  (-update
    ([this bytes-or-str]
      (let [digest (.clone (.-msg-digest this))
            charset (.-charset this)]
        (loop [charset charset
               bytes-or-str bytes-or-str]
          (if-let [bytes-or-str (seq bytes-or-str)]
            (let [s (first bytes-or-str)]
              (if (keyword? s)
                (recur (charset-name (name s)) (rest bytes-or-str))
                (do
                  (when-not (nil? s)
                    (.update digest 
                             (cond
                              (char? s) (.getBytes (str s) charset)
                              (string? s) (.getBytes s charset)
                              (= (type s) clojure.core.Vec) (byte-array s)
                              :else s)))
                    (recur charset (rest bytes-or-str)))))
            (TMessageDigest. digest charset))))))
  (-digest
    ([this] 
      (.digest (.clone (.-msg-digest this))))
    ([this bytes-or-str] 
      (-digest (-update this bytes-or-str))))
  (algorithm
    ([this] 
      (.getAlgorithm (.-msg-digest this))))
  (charset
    ([this] 
      (.-charset this))))


(defn digests-equal?
  "Returns true if this digest is equal to all the individual digests.
  Returns false otherwise.
  Input is either a message-digest object (TMessageDigest) 
  or a digest result as a byte-array.
  Does a simple byte-compare of the individual digest-values"
  [this & digests]
  (let [d-this (or 
                (and (= (type this) clj.security.message_digest.TMessageDigest)
                     (-digest this))
                this)]
    (every? (fn [d] (java.security.MessageDigest/isEqual 
                      d-this 
                      (or 
                        (and (= (type d) clj.security.message_digest.TMessageDigest)
                             (-digest d))
                        d)))
            digests)))


(defn update 
  "Updates the message digest accumulator by digesting/secure-hashing the passed arguments.
  this - a TMessageDigest object, created with factory-fn \"message-digest\"
  bytes-or-str - 0, 1 or more arguments to digest of type string, char or byte-array.
  Digest algorithm and charset are configured in TMessageDigest object.
  Returns a new updated TMessageDigest object."
  ;; helper fn to cater for the lack of varargs support in protocols
  ([] (update (message-digest)))
  ([this & bytes-or-str] 
    (cond
      (= (type this) clj.security.message_digest.TMessageDigest)
        (-update this bytes-or-str)
      (keyword? this)
        (apply update (message-digest this) bytes-or-str)
      :else
        (apply update (message-digest) this bytes-or-str))))


(defn digest 
  "Returns a byte-array of the value for the accumulated message digest.
  this - a TMessageDigest object or the first argument to digest
  bytes-or-str - 0, 1 or more arguments to digest of type string, char or byte-array.
  If first argument is not a TMessageDigest object, then a new one will be dynamically 
  created and that first argument is seen as the first value to digest.
  The digest algorithm and charset are either pre-configured in the passed 
  TMessageDigest object, or taken from the *default-message-digest* and 
  *default-charset* vars if the TMessageDigest object is created dynamically.
  Note that any passed TMessageDigest object is not changed."
  ;; helper fn to cater for the lack of varargs support in protocols
  ([] (-digest (message-digest)))
  ([this & bytes-or-str] 
    (cond
      (= (type this) clj.security.message_digest.TMessageDigest)
        (-digest this bytes-or-str)
      (keyword? this)
        (apply digest (message-digest this) bytes-or-str)
      :else
        (apply digest (message-digest) this bytes-or-str))))


(defn ->hex 
  "Returs a string with the hex-value equivalents of the given byte-array."
  [some-bytes]
  (clojure.string/upper-case 
    (apply str (map (partial format "%02x") (->bytes some-bytes)))))

(defn hex->bytes 
  "Returns a byte array for a string of hexadecimals."
  [hex-str]
  (into-array Byte/TYPE
              (map (fn [[x y]]
                (unchecked-byte (Integer/parseInt (str x y) 16)))
                (partition 2 hex-str))))

(defn ->base64 
  [some-bytes]
  (org.apache.commons.codec.binary.Base64/encodeBase64String some-bytes))

(defn ->base32 
  [some-bytes]
  (.encodeToString (org.apache.commons.codec.binary.Base32.) some-bytes))
