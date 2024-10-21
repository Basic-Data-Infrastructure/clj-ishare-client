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
            [clojure.test :refer [deftest is testing are]]
            [clojure.java.io :as io]
            [org.bdinetwork.ishare.client :as client]
            [org.bdinetwork.ishare.jwt :as jwt]
            [org.bdinetwork.ishare.test-helper :refer [run-exec]]))

(defn- ->x5c [v]
  (->> [v "ca"]
       (map #(str "pem/" % ".cert.pem"))
       (mapcat (comp client/x5c io/resource))))

(defn- ->key [v]
  (-> (str "pem/" v ".key.pem") io/resource client/private-key))

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
   :ishare/satellite-base-url aa-url})

(defn test-get-token [c token]
  (testing "getting an access token"
    (let [{:keys [uri exception]} (<!! c)]
      (when exception
        (throw (ex-info "Unexpected exception during access-token call"
                        {:token token}
                        exception)))
      (is (= (str aa-url "/connect/token") (str uri)))

      (>!! c {:status  200
              :uri     uri
              :headers {"content-type" "application/json"}
              :body    (json/json-str {"access_token" token
                                       "token_type"   "Bearer",
                                       "expires_in"   3600})}))))

(deftest parties
  (testing "expired parties token"
    (let [[c r] (run-exec (client/parties-request client-data nil))]

      (test-get-token c "aa-token")

      (testing "Getting parties"
        (let [{:keys [uri] :as req} (<!! c)]
          (is (= (str aa-url "/parties")
                 (str uri) ;; is a java.net.URI
                 ))
          (is (= "Bearer aa-token" (get-in req [:headers "Authorization"])))

          (>!! c {:status  200
                  :uri     uri
                  :headers {"content-type" "application/json"}
                  :body    (json/json-str
                            {"parties_token"
                             (jwt/make-jwt {:iat 0
                                            ;; Too old; will be rejected, since make-jwt
                                            ;; will set exp to iat + 30 seconds.
                                            :iss aa-eori
                                            :sub aa-eori
                                            :aud client-eori}
                                           aa-private-key
                                           aa-x5c)})})))

      (let [{:keys [exception]} (<!! c)]
        (is exception
            "Exception raised")
        (is (s/starts-with? (ex-message exception)
                            "Token is expired")))

      (is (nil? @r))))

  (testing "wrong certificate chain"
    (let [[c r] (run-exec (client/parties-request client-data {"active_only" "true"}))]

      (test-get-token c "aa-token")

      (testing "getting parties"
        (let [{:keys [uri] :as req} (<!! c)]
          (is (= (str aa-url "/parties?active_only=true") (str uri)))
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
                                           ;; we use `client-x5c`
                                           ;; instead of `aa-x5c`, so
                                           ;; the certificate chain
                                           ;; does not match the
                                           ;; private key.
                                           ;;
                                           ;; This should raise an
                                           ;; exception in the client
                                           client-x5c)})})))

      (let [{:keys [exception]} (<!! c)]
        (is exception
            "Exception raised")
        (is (= "Message seems corrupt or manipulated"
               (ex-message exception))))

      (is (nil? @r))))

  (testing "valid parties token"
    (let [[c r] (run-exec (client/parties-request client-data {"name" "Party Name"}))]

      (test-get-token c "aa-token")

      (testing "getting parties"
        (let [{:keys [uri] :as req} (<!! c)]
          (is (= (str aa-url "/parties?name=Party+Name") (str uri)))
          (is (= "Bearer aa-token" (-> req :headers (get "Authorization"))))

          (>!! c {:status  200
                  :uri     (:uri req)
                  :headers {"content-type" "application/json"}
                  :body    (json/json-str
                            {"parties_token"
                             (jwt/make-jwt {:iss          aa-eori
                                            :sub          aa-eori
                                            :aud          client-eori
                                            :parties_info {:total_count 1,
                                                           :pageCount 1,
                                                           :count 1,
                                                           :data [{:party_id "EU.EORI.CLIENT"
                                                                   :adherence {:status "Active"}}]}}
                                           aa-private-key
                                           aa-x5c)})})))

      (is (= 1 (-> @r :ishare/result :parties_info :count))))))

(deftest delegation
  (testing "Getting delegation evidence from an AR"
    (let [[c r] (run-exec (client/delegation-evidence-request client-data
                                                              {:delegationRequest
                                                               {:policyIssuer client-eori}}))]
      (test-get-token c "aa-token")

      (testing "Getting party info to retreive AR location"
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

      (testing "Get token at AR"
        (let [{:keys [uri]} (<!! c)]
          (is (= (str ar-url "/connect/token")
                 (str uri) ;; uri is a java.net.URI
                 ))

          (>!! c {:status  200
                  :uri     uri
                  :headers {"content-type" "application/json"}
                  :body    (json/json-str {"access_token" "ar-token"
                                           "token_type"   "Bearer",
                                           "expires_in"   3600})})))

      (testing "Get delegation evidence from AR"
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

(def base-request
  (assoc client-data
         :ishare/base-url "https://example.com/api"
         :ishare/server-id "EU.EORI.SERVERID"))

(def delegation-request
  {:delegationRequest {:policyIssuer client-eori}})

(defn clean-request
  [req]
  (-> req
      (dissoc :ishare/message-type
              :ishare/params
              :ishare/party-id)
      (update :form-params dissoc "client_assertion")))

(deftest deprecated-api
  (testing "Deprecated ishare->http-request middleware still works"
    (are [new-api old-api] (= (clean-request new-api)
                              (clean-request old-api))

      (client/access-token-request base-request)
      (client/ishare->http-request (assoc base-request
                                          :ishare/message-type :access-token))

      (client/parties-request base-request {"name" "foo"})
      (client/ishare->http-request (assoc base-request
                                          :ishare/message-type :parties
                                          :ishare/params {"name" "foo"}))

      (client/party-request base-request "foo")
      (client/ishare->http-request (assoc base-request
                                          :ishare/message-type :party
                                          :ishare/party-id "foo"))

      (client/trusted-list-request base-request)
      (client/ishare->http-request (assoc base-request
                                          :ishare/message-type :trusted-list))

      (client/capabilities-request base-request)
      (client/ishare->http-request (assoc base-request
                                          :ishare/message-type :capabilities))

      (client/delegation-evidence-request base-request delegation-request)
      (client/ishare->http-request (assoc base-request
                                          :ishare/message-type :delegation
                                          :ishare/policy-issuer client-eori
                                          :ishare/params delegation-request)))))
