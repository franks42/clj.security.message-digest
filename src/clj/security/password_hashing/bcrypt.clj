(ns clj.security.password-hashing.bcrypt
  "clj.security.password-hashing.bcrypt is a clojure wrapper for jBCrypt
  
  BCrypt implements OpenBSD-style Blowfish password hashing using
  the scheme described in \"A Future-Adaptable Password Scheme\" by
  Niels Provos and David Mazieres.
  
  This password hashing system tries to thwart off-line password
  cracking using a computationally-intensive hashing algorithm,
  based on Bruce Schneier's Blowfish cipher. The work factor of
  the algorithm is parameterised, so it can be increased as
  computers get faster.
  
  Usage is really simple. To hash a password for the first time,
  call the hash-password function with a random salt, like this:
  
    (require '(clj.security.password-hashing [bcrypt :as bcrypt]))
    (def pw-hash (bcrypt/hash-password plain_password (bcrypt/gen-salt)))
  
  To check whether a plaintext password matches one that has been
  hashed previously, use the password-valid? method:
  
    (if (bcrypt/password-valid? candidate-password stored_hash)
      (println \"It matches\")
      (println \"It does not match\"))
      
  The gensalt() method takes an optional parameter (log_rounds)
  that determines the computational complexity of the hashing:
  
    (def strong-salt (bcrypt/gen-salt 10))
    (def stronger-salt (bcrypt/gen-salt 12))
  
  The amount of work increases exponentially (2**log_rounds), so 
  each increment is twice as much work. The default log_rounds is
  10, and the valid range is 4 to 31.
  
  jBCrypt author Damien Miller
  jBCrypt version 0.2
  clj.security.password-hashing.bcrypt wrapper-author Frank Siebenlist.
 "
  (:require [clojure.string])
  (:import [clj.security.password_hashing.BCrypt]))

;; java interface repl example
;; user=> (clj.security.password_hashing.BCrypt/gensalt)
;; "$2a$10$6a0oNyEkezpEItuDlty2pu"
;; user=> (clj.security.password_hashing.BCrypt/gensalt 12)
;; "$2a$12$3WUyxDZ1zQ17TxmciEb2ju"
;; user=> (clj.security.password_hashing.BCrypt/hashpw "jaja" (clj.security.password_hashing.BCrypt/gensalt))
;; "$2a$10$WH2w4aPY92T1xwlDJEQABOH57qcy3nIy1f4bQ/sYBQmGzW739w1tm"
;; user=> (clj.security.password_hashing.BCrypt/checkpw "jaja" "$2a$10$WH2w4aPY92T1xwlDJEQABOH57qcy3nIy1f4bQ/sYBQmGzW739w1tm")
;; true
;; user=> (clj.security.password_hashing.BCrypt/checkpw "jaja" "$2a$10$WH2w4aPY92T1xwlDJEQABOH57qcy3nIy1f4bQ/sYBQmGzW739w1tp")
;; false
;; user=> (clj.security.password_hashing.BCrypt/checkpw "jaja" "$2a$10$WH2w4aPY92T1xwlDJEQABOH57qcy3nIy1f4bQ/sYBQmGzW739w1tm")
;; true
;; user=> (clj.security.password_hashing.BCrypt/checkpw "jajaa" "$2a$10$WH2w4aPY92T1xwlDJEQABOH57qcy3nIy1f4bQ/sYBQmGzW739w1tm")
;; false

(defn gen-salt
  "Generate a salt for use with bcrypt/hash-password
  log-rounds - (optional) the log2 of the number of rounds of hashing to apply
             - the work factor therefore increases as 2**log_rounds.
               (defaults to 10)
  random     - (optional) instance of Secure.Random to use
  Returns	an encoded salt value as a (base64-encoded) string"
  ([]
    (clj.security.password_hashing.BCrypt/gensalt))
  ([log-rounds]
    (clj.security.password_hashing.BCrypt/gensalt log-rounds))
  ([log-rounds random]
    (clj.security.password_hashing.BCrypt/gensalt log-rounds random)))


(defn hash-password
  "Hash a password using the OpenBSD bcrypt scheme
  password - the plain-text password to hash as a string
  salt     - (optional) the salt to hash with (perhaps generated using bcrypt/gen-salt)
             as a (base64-encoded) string
           - uses (bcrypt/gen-salt) for default
  Returns the hashed password as a (base64-encoded) string"
  ([password]
    (clj.security.password_hashing.BCrypt/hashpw password (gen-salt)))
  ([password salt]
    (clj.security.password_hashing.BCrypt/hashpw password salt)))


(defn password-valid?
  "Predicate to check that a plaintext password matches a previously hashed one.
  candidate-password - the plaintext password to verify as a string
  hashed-password    - the previously hashed password as a (base64-encoded) string
  Returns true if the passwords match, false otherwise"
  [candidate-password hashed-password]
  (clj.security.password_hashing.BCrypt/checkpw candidate-password hashed-password))


;; aliases to satisfy the java api equivalent methods... for those who care...
(def gensalt #'gen-salt)
(def hashpw #'hash-password)
(def checkpw #'password-valid?)
