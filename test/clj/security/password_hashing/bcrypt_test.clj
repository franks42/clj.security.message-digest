(ns clj.security.password-hashing.bcrypt-test
  ""
  (:use clojure.test
;;         midje.sweet
        clj.security.password-hashing.bcrypt))

(def s0 (gen-salt))
(def s10 (gen-salt 10))
(def s11 (gen-salt 11))
(def s12 (gen-salt 12))
(def s10R (gen-salt 10 (java.security.SecureRandom.)))

(def h (hash-password "jajajaja"))
(def h0 (hash-password "jajajaja" s0))
(def h10 (hash-password "jajajaja" s10))
(def h11 (hash-password "jajajaja" s11))
(def h12 (hash-password "jajajaja" s12))
(def h10R (hash-password "jajajaja" s10R))

(deftest bcrypt-test
  (testing "bcrypt"
    (is (password-valid? "jajajaja" h))
    (is (password-valid? "jajajaja" h0))
    (is (password-valid? "jajajaja" h10))
    (is (password-valid? "jajajaja" h11))
    (is (password-valid? "jajajaja" h12))
    (is (password-valid? "jajajaja" h10R))
    (is (not (password-valid? "jajajnee" h)))
    (is (not (password-valid? "jajajnee" h12)))
    (is (not (password-valid? "jajajnee" h10R)))
;;     (is (password-valid? "jajajnee" h10R))  ;; just checking the test
    ))
