(ns clj.security.message-digest-test
  (:use clojure.test
;;         midje.sweet
        clj.security.message-digest))

(deftest nist-test
  (testing "nist test data: \"http://www.nsrl.nist.gov/testdata/\""
    (is (= (bytes2hex (digest (make-message-digest :SHA-1 :UTF-8) "abc"))
           "A9993E364706816ABA3E25717850C26C9CD0D89D"))
    (is (= (bytes2hex (digest (make-message-digest :SHA-1 :UTF-8) 
                    "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"))
           "84983E441C3BD26EBAAE4AA1F95129E5E54670F1"))
    (is (= (bytes2hex (apply digest (make-message-digest :SHA-1 :UTF-8)
                                (repeat 1000000 "a")))
           "34AA973CD4C4DAA4F61EEB2BDBAD27316534016F"))

    (is (= (bytes2hex (digest (make-message-digest :MD5 :UTF-8) "abc"))
           "900150983CD24FB0D6963F7D28E17F72"))
    (is (= (bytes2hex (digest (make-message-digest :MD5 :UTF-8)
                    "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"))
           "8215EF0796A20BCAAAE116D3876C664A"))
    (is (= (bytes2hex (apply digest (make-message-digest :MD5 :UTF-8)
                                (repeat 1000000 "a")))
           "7707D6AE4E027C70EEA2A935C2296F21"))

    (is (= (bytes2hex (digest (make-message-digest :SHA-256 :UTF-8) "abc"))
           "BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD"))
    (is (= (bytes2hex (digest (make-message-digest :SHA-256 :UTF-8)
                    "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"))
           "248D6A61D20638B8E5C026930C3E6039A33CE45964FF2167F6ECEDD419DB06C1"))
    (is (= (bytes2hex (apply digest (make-message-digest :SHA-256 :UTF-8)
                                (repeat 1000000 "a")))
           "CDC76E5C9914FB9281A1C7E284D73E67F1809A48A497200E046D39CCC7112CD0"))
      ))


(deftest wiki-test
  (testing "wiki test data: \"http://en.wikipedia.org/wiki/SHA-1\""
    (is (= (bytes2hex (digest (make-message-digest :SHA-1 :UTF-8) 
                    "The quick brown fox jumps over the lazy dog"))
           "2FD4E1C67A2D28FCED849EE1BB76E7391B93EB12"))
    (is (= (bytes2hex (digest (make-message-digest :SHA-1 :UTF-8) ""))
           "DA39A3EE5E6B4B0D3255BFEF95601890AFD80709"))

    (is (= (bytes2hex (digest (make-message-digest :MD5 :UTF-8) 
                    "The quick brown fox jumps over the lazy dog"))
           "9E107D9D372BB6826BD81D3542A419D6"))
    (is (= (bytes2hex (digest (make-message-digest :MD5 :UTF-8) ""))
           "D41D8CD98F00B204E9800998ECF8427E"))

    (is (= (bytes2hex (digest (make-message-digest :SHA-256 :UTF-8) 
                    "The quick brown fox jumps over the lazy dog"))
           "D7A8FBB307D7809469CA9ABCB0082E4F8D5651E46D3CDB762D02D0BF37C9E592"))
    (is (= (bytes2hex (digest (make-message-digest :SHA-256 :UTF-8) ""))
           "E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855"))

    (is (= (bytes2hex (digest (make-message-digest :SHA-512 :UTF-8) 
                    "The quick brown fox jumps over the lazy dog"))
           "07E547D9586F6A73F73FBAC0435ED76951218FB7D0C8D788A309D785436BBB642E93A252A954F23912547D1E8A3B5ED6E1BFD7097821233FA0538F3DB854FEE6"))
    (is (= (bytes2hex (digest (make-message-digest :SHA-512 :UTF-8) ""))
           "CF83E1357EEFB8BDF1542850D66D8007D620E4050B5715DC83F4A921D36CE9CE47D0D13C5D85F2B0FF8318D2877EEC2F63B931BD47417A81A538327AF927DA3E"))
      ))


(def d0 (make-message-digest :MD5 :UTF-8))
(def md5-abc (hex2bytes "900150983CD24FB0D6963F7D28E17F72"))

(deftest interface-test
  (testing "testing combinations of update and digest with different data type for arguments."
    (is (digests-equal? (digest (make-message-digest :MD5 :UTF-8) "abc") md5-abc))
    (is (digests-equal? (digest (update (make-message-digest :MD5 :UTF-8) "abc")) md5-abc))
    (is (digests-equal? (digest d0 "abc") md5-abc))
    (is (digests-equal? (digest (update d0 "abc")) md5-abc))
    (is (digests-equal? (binding [*default-digest-algorithm* :MD5
                    *default-charset* :UTF-8] 
            (digest "abc")) md5-abc))
    (is (digests-equal? (hex2bytes "900150983CD24FB0D6963F7D28E17F72") md5-abc))
  ))

