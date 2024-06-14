;;; SPDX-FileCopyrightText: 2024 Jomco B.V.
;;; SPDX-FileCopyrightText: 2024 Topsector Logistiek
;;; SPDX-FileContributor: Joost Diepenmaat <joost@jomco.nl>
;;; SPDX-FileContributor: Remco van 't Veer <remco@jomco.nl>
;;;
;;; SPDX-License-Identifier: AGPL-3.0-or-later

(ns org.bdinetwork.ishare.client-test
  (:require [clojure.core.async :refer [<!! >!!] :as async]
            [clojure.data.json :as json]
            [clojure.string :as s]
            [clojure.test :refer [deftest is testing]]
            [clojure.java.io :as io]
            [org.bdinetwork.ishare.client :as sut]
            [org.bdinetwork.ishare.jwt :as jwt]
            [org.bdinetwork.ishare.test-helper :refer [run-exec]]))

(defn- ->x5c [v]
  (->> [v "ca"]
       (map #(str "pem/" % ".cert.pem"))
       (mapcat (comp sut/x5c io/resource))))

(defn- ->key [v]
  (-> (str "pem/" v ".key.pem") io/resource sut/private-key))

(def client-eori "EU.EORI.CLIENT")
(def client-x5c (->x5c "client"))
(def client-private-key (->key "client"))

(def aa-eori "EU.EORI.AA")
(def aa-url "https://aa.example.com")
(def aa-x5c (->x5c "aa"))
(def aa-private-key (->key "aa"))

(def ar-eori "EU.EORI.AR")
(def ar-url "https://ar.example.com")
(def ar-x5c (->x5c "ar"))
(def ar-private-key (->key "ar"))

(def dataspace-id "test")

(def client-data
  {:ishare/client-id          client-eori
   :ishare/private-key        client-private-key
   :ishare/x5c                client-x5c
   :ishare/dataspace-id       dataspace-id
   :ishare/satellite-id       aa-eori
   :ishare/satellite-endpoint aa-url})

(defn test-get-token [c token]
  (testing "getting an access token"
    (let [{:keys [uri]} (<!! c)]
      (is (= (str aa-url "/connect/token") (str uri)))

      (>!! c {:status  200
              :uri     uri
              :headers {"content-type" "application/json"}
              :body    (json/json-str {"access_token" token
                                       "token_type"   "Bearer",
                                       "expires_in"   3600})}))))

(deftest parties
  (testing "expired parties token"
    (let [[c r] (run-exec (-> client-data
                              (assoc :ishare/message-type :parties)))]

      (test-get-token c "aa-token")

      (testing "getting parties"
        (let [{:keys [uri] :as req} (<!! c)]
          (is (= (str aa-url "/parties") (str uri)))
          (is (= "Bearer aa-token" (get-in req [:headers "Authorization"])))

          (>!! c {:status  200
                  :uri     (:uri req)
                  :headers {"content-type" "application/json"}
                  :body    (json/json-str
                            {"parties_token"
                             (jwt/make-jwt {:iat 0
                                            :iss aa-eori
                                            :sub aa-eori
                                            :aud client-eori}
                                           aa-private-key
                                           aa-x5c)})})))

      (let [{:keys [exception]} (<!! c)]
        (is (s/starts-with? (.getMessage exception) "Token is expired")))

      (is (nil? @r))))

  (testing "wrong certificate chain"
    (let [[c r] (run-exec (-> client-data
                              (assoc :ishare/message-type :parties)))]

      (test-get-token c "aa-token")

      (testing "getting parties"
        (let [{:keys [uri] :as req} (<!! c)]
          (is (= (str aa-url "/parties") (str uri)))
          (is (= "Bearer aa-token" (get-in req [:headers "Authorization"])))

          (>!! c {:status  200
                  :uri     (:uri req)
                  :headers {"content-type" "application/json"}
                  :body    (json/json-str
                            {"parties_token"
                             (jwt/make-jwt {:iss aa-eori
                                            :sub aa-eori
                                            :aud client-eori}
                                           aa-private-key
                                           client-x5c)})})))

      (let [{:keys [exception]} (<!! c)]
        (is (= "Message seems corrupt or manipulated"
               (.getMessage exception))))

      (is (nil? @r))))

  (testing "valid parties token"
    (let [[c r] (run-exec (-> client-data
                              (assoc :ishare/message-type :parties)))]

      (test-get-token c "aa-token")

      (testing "getting parties"
        (let [{:keys [uri] :as req} (<!! c)]
          (is (= (str aa-url "/parties") (str uri)))
          (is (= "Bearer aa-token" (-> req :headers (get "Authorization"))))

          (>!! c {:status  200
                  :uri     (:uri req)
                  :headers {"content-type" "application/json"}
                  :body    (json/json-str
                            {"parties_token"
                             (jwt/make-jwt {:iss          aa-eori
                                            :sub          aa-eori
                                            :aud          client-eori
                                            :parties_info {:total_count 0, :pageCount 0, :count 0, :data []}}
                                           aa-private-key
                                           aa-x5c)})})))

      (is (= 0 (-> @r :ishare/result :parties_info :count))))))

(deftest delegation
  (testing "getting delegation evidence from an AR"
    (let [[c r] (run-exec (-> client-data
                              (assoc :ishare/message-type :delegation
                                     :ishare/policy-issuer client-eori)))]
      (test-get-token c "aa-token")

      (testing "getting client"
        (let [{:keys [uri] :as req} (<!! c)]
          (is (= (str aa-url "/parties/" client-eori) (str uri)))
          (is (= "Bearer aa-token" (-> req :headers (get "Authorization"))))

          (>!! c {:status  200
                  :uri     (:uri req)
                  :headers {"content-type" "application/json"}
                  :body    (json/json-str
                            {"party_token"
                             (jwt/make-jwt {:iss        aa-eori
                                            :sub        aa-eori
                                            :aud        client-eori
                                            :party_info {:authregistery [{:dataspaceID              "other ds-id"
                                                                          :authorizationRegistryID  "EU.EORI.OTHER"
                                                                          :authorizationRegistryUrl "https://other.example.com"}
                                                                         {:dataspaceID              dataspace-id
                                                                          :authorizationRegistryID  ar-eori
                                                                          :authorizationRegistryUrl ar-url}
                                                                         {:dataspaceID              "random ds-id"
                                                                          :authorizationRegistryID  "EU.EORI.RANDOM"
                                                                          :authorizationRegistryUrl "https://random.example.com"}]}}
                                           aa-private-key
                                           aa-x5c)})})))

      (testing "get token at AR"
        (let [{:keys [uri]} (<!! c)]
          (is (= (str ar-url "/connect/token") (str uri)))

          (>!! c {:status  200
                  :uri     uri
                  :headers {"content-type" "application/json"}
                  :body    (json/json-str {"access_token" "ar-token"
                                           "token_type"   "Bearer",
                                           "expires_in"   3600})})))

      (testing "delegation call"
        (let [{:keys [uri] :as req} (<!! c)]
          (is (= (str ar-url "/delegation") (str uri)))
          (is (= "Bearer ar-token" (get-in req [:headers "Authorization"])))

          (>!! c {:status  200
                  :uri     uri
                  :headers {"content-type" "application/json"}
                  :body    (json/json-str
                            {"delegation_token"
                             (jwt/make-jwt {:iss                ar-eori
                                            :sub                ar-eori
                                            :aud                client-eori
                                            :delegationEvidence "test"}
                                           ar-private-key
                                           ar-x5c)})})))

      (is (= "test" (-> @r :ishare/result :delegationEvidence))))))
