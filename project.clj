(defproject org.clojars.franks42/clj.security.message-digest "0.1.0-SNAPSHOT"
  :description "Functional message digest interface."
  :url "https://github.com/franks42/clj.security.message-digest"
  :license {:name "Eclipse Public License"
            :url "http://www.eclipse.org/legal/epl-v10.html"}
  :dependencies [[org.clojure/clojure "1.5.0"]
                 [commons-codec "1.5"]]
  :dev-dependencies [[clj-ns-browser "1.3.1"]
                     [codox "0.6.4"]
                     ]
  :plugins [[codox "0.6.4"]
            ]
  :profiles {:1.3 {:dependencies [[org.clojure/clojure "1.3.0"]]}
             :1.4 {:dependencies [[org.clojure/clojure "1.4.0"]]}
             :master {:dependencies [[org.clojure/clojure "1.5.0"]]}
             :dev {:dependencies [[clj-ns-browser "1.3.1"]]}}
  :aliases  {"all" ["with-profile" "dev:dev,1.3:dev,1.4:dev,1.4:dev,master"]}
  )
