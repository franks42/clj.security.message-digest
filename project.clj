(defproject org.clojars.franks42/clj.security.message-digest "0.1.0-SNAPSHOT"
  :description "Functional message digest interface."
  :url "https://github.com/franks42/clj.security.message-digest"
  :license {:name "Eclipse Public License"
            :url "http://www.eclipse.org/legal/epl-v10.html"}
  :dependencies [[org.clojure/clojure "1.6.0"]
                 [commons-codec "1.10"]]
  :dev-dependencies [[clj-ns-browser "1.3.2-SNAPSHOT"]
                     [codox "0.8.12"]
                     ]
  :java-source-paths ["src"]
  :java-source-path "src"
  :plugins [[codox "0.8.12"]
            ]
  :profiles {:master {:dependencies [[org.clojure/clojure "1.6.0"]]}
             :dev {:dependencies [[clj-ns-browser "1.3.2-SNAPSHOT"]]}}
  :aliases  {"all" ["with-profile" "dev:dev,master"]}
  )
