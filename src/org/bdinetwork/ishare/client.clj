;;; SPDX-FileCopyrightText: 2024 Jomco B.V.
;;; SPDX-FileCopyrightText: 2024 Topsector Logistiek
;;; SPDX-FileContributor: Joost Diepenmaat <joost@jomco.nl>
;;; SPDX-FileContributor: Remco van 't Veer <remco@jomco.nl>
;;;
;;; SPDX-License-Identifier: AGPL-3.0-or-later

(ns org.bdinetwork.ishare.client
  (:require [babashka.http-client :as http]
            [babashka.http-client.interceptors :as interceptors]
            [babashka.json :as json]
            [buddy.core.keys :as keys]
            [clojure.string :as string]
            [org.bdinetwork.ishare.jwt :as jwt]
            [clojure.tools.logging.readable :as log])
  (:import (java.net URI)))

(defn private-key
  "Read private key from file."
  [key-file]
  (keys/private-key key-file))

;; From https://dev.ishareworks.org/reference/jwt.html#refjwt
;;
;;  "Signed JWTs MUST contain an array of the complete certificate
;;   chain that should be used for validating the JWT’s signature in
;;   the x5c header parameter up until an Issuing CA is listed from
;;   the iSHARE Trusted List."
;;
;; Does this mean we don't need to include the trusted CAs in the x5c
;; chain?

(defn x5c
  "Read chain file into vector of certificates."
  [cert-file]
  (->> (-> cert-file
           slurp
           (string/replace-first #"(?s)\A.*?-+BEGIN CERTIFICATE-+\s+" "")
           (string/replace #"(?s)\s*-+END CERTIFICATE-+\s*\Z" "")
           (string/split #"(?s)\s*-+END CERTIFICATE-+.*?-+BEGIN CERTIFICATE-+\s*"))
       (mapv #(string/replace % #"\s+" ""))))

(def unsign-token-interceptor
  {:name     ::unsign-token
   :description
   "A request with `:ishare/unsign prop` will unsign the jwt under `prop` in response body"
   :response (fn unsign-token-response [response]
               (let [k (get-in response [:request :ishare/unsign-token])]
                 (if (and k (get-in response [:body k]))
                   (update-in response [:body k] jwt/unsign-token)
                   response)))})

(defn json-response?
  [response]
  (when-let [type (get-in response [:headers "content-type"])]
    (string/starts-with? type "application/json")))

(def json-interceptor
  {:name     ::json
   :description
   "A request with `:as :json` will automatically get the
   \"application/json\" accept header and the response is decoded as JSON.

    When :json-params is present in the request, an
    \"application/json\" content-type header is added and the
    json-params will be serialized as JSON and used as the request
    body."
   :request  (fn json-request [{:keys [as json-params] :as request}]
               (cond-> request
                 (= :json as)
                 (-> (assoc-in [:headers :accept] "application/json")
                     ;; Read body as :string
                     ;; Mark request as amenable to json decoding
                     (assoc :as :string ::json true))

                 (contains? request :json-params) ;; use contains? to support `:json-params nil`
                 (-> (assoc-in [:headers "content-type"] "application/json")
                     (assoc :body (json/write-str json-params)))))
   :response (fn json-response [response]
               (if (and (get-in response [:request ::json])
                        (json-response? response))
                 (update response :body #(json/read-str % {:key-fn identity}))
                 response))})

(def bearer-token-interceptor
  {:name     ::bearer-token
   :description
   "A request with a non-nil `:ishare/bearer-token` will get an Authorization
   header for the bearer token added."
   :request  (fn bearer-token-request [{:ishare/keys [bearer-token] :as request}]
               (if bearer-token
                 (assoc-in request [:headers "Authorization"] (str "Bearer " bearer-token))
                 request))})

(declare exec)

(def fetch-bearer-token-interceptor
  {:name    ::fetch-bearer-token
   :doc     "When request has no :ishare/bearer-token, fetch it from the endpoint.
When bearer token is not needed, provide a `nil` token"
   :request (fn fetch-bearer-token-request [request]
              (if (contains? request :ishare/bearer-token)
                request
                (let [response (-> request
                                   (select-keys [:ishare/base-url
                                                 :ishare/client-id
                                                 :ishare/server-id
                                                 :ishare/x5c
                                                 :ishare/private-key])
                                   (assoc :ishare/message-type :access-token)
                                   exec)
                      token (:ishare/result response)]
                  (when-not token
                    ;; FEEDBACK: bij invalid client op /token komt 202 status terug?
                    (throw (ex-info "Error fetching access token" {:response response})))
                  (assoc request
                         :ishare/bearer-token token))))})

(def lens-interceptor
  {:name     ::lens
   :description
   "If request contains :ishare/lens path, put the object at path in
   reponse, under :ishare/result"
   :response (fn lens-response [response]
               (if-let [path (get-in response [:request :ishare/lens])]
                 (assoc response :ishare/result (get-in response path))
                 response))})

(def ^:dynamic log-interceptor-atom nil)

(def log-interceptor
  {:name     ::log
   :response (fn log-response [r]
               (when log-interceptor-atom
                 (swap! log-interceptor-atom conj r))
               r)})

(def logging-interceptor
  {:name     ::logging
   :response (fn logging-response [{:keys [request] :as response}]
               (log/debug {:request  (select-keys request [:method :uri])
                           :response (select-keys response [:status])})
               response)})


(defn redact-path
  [r p]
  (if (get-in r p)
    (assoc-in r p "REDACTED")
    r))

(defn redact-body
  "Remove sensitive params from request body (for logging)"
  [body]
  (if (string? body)
    (string/replace body #"(client_assertion=)[^&]+" "$1REDACTED")
    body))

(defn redact-request
  [request]
  (-> request
      (redact-path [:ishare/private-key])
      (redact-path [:ishare/x5c])
      (dissoc :interceptors)
      (redact-path [:form-params "client_assertion"])
      (update :headers redact-path ["authorization"])
      (update :body redact-body)
      (dissoc :client)))

(def unexceptional-statuses
  #{200 201 202 203 204 205 206 207 300 301 302 303 304 307})

(def throw-on-exceptional-status-code
  "Response: throw on exceptional status codes. Strips out client info and private information"
  {:name ::throw-on-exceptional-status-code
   :response (fn throw-on-exceptional-status-code-response [resp]
               (if-let [status (:status resp)]
                 (if (or (false? (some-> resp :request :throw))
                         (contains? unexceptional-statuses status))
                   resp
                   (throw (ex-info (str "Exceptional status code: " status) (update resp :request redact-request))))
                 resp))})

(defn resolve-uri [base-url path]
  (let [base-url (if  (string/ends-with? base-url "/")
                   base-url
                   (str base-url "/"))]
    (-> base-url
        (URI.)
        (.resolve (URI. path))
        (.normalize)
        (str))))

(def build-uri-interceptor
  {:name ::build-uri
   :request (fn build-uri-request [{:keys [path ishare/base-url] :as request}]
              (if (and path base-url)
                (assoc request :uri (resolve-uri base-url path))
                request))})



;; This is a workaround
;;
;; The current (as of 2024-10-02) iSHARE satellite implementations
;; return out-of-spec information about a party's authorization
;; registries.
;;
;; According to the v2.0 specification, this information should be
;; provided as a collection under the `auth_registries` key -- see the
;; #/components/schemas/Party entry in iSHARE scheme 2.0 --
;; https://app.swaggerhub.com/apis/iSHARE/iSHARE_Scheme_Specification/2.0#/Party
;; but the satellite actually returns this information in a different
;; form under the `authregistery` key, which is undocumented.

(defn- party-info->auth-registry
  "Workaround `:auth_registries` data is provided as `:authregistery` in current ishare satellite."
  [{:keys [auth_registries authregistery] :as _party_info}]
  (or auth_registries
      (map (fn upgrade-authregistery
             [{:keys [dataspaceID authorizationRegistryName
                      authorizationRegistryID authorizationRegistryUrl]}]
             {:dataspace_id dataspaceID
              :id           authorizationRegistryID
              :name         authorizationRegistryName
              :url          authorizationRegistryUrl})
           authregistery)))

(defn- fetch-issuer-ar
  "If request contains `policy-issuer` and no `server-id` + `base-url`,
  set `server-id` and `base-url` to issuer's authorization registry
  for dataspace."
  [{:ishare/keys [policy-issuer dataspace-id server-id base-url]
    :as          request}]
  (if (or (not (and policy-issuer dataspace-id))
          (and server-id base-url))
    request
    (if-let [{:keys [name id url]}
             (->> (-> request
                      ;; select only necessary from original request.
                      (select-keys [:ishare/x5c
                                    :ishare/private-key
                                    :ishare/client-id
                                    :ishare/satellite-id
                                    :ishare/satellite-base-url])
                      (assoc :ishare/message-type :party
                             :ishare/party-id policy-issuer))
                  exec
                  :ishare/result
                  :party_info
                  (party-info->auth-registry)
                  (filter #(= dataspace-id (:dataspace_id %)))
                  first)]
      (assoc request
             :ishare/server-id id
             :ishare/server-name name
             :ishare/base-url url)
      (throw (ex-info (str "Can't find authorization register for " policy-issuer)
                      {:dataspace-id dataspace-id
                       :policy-issuer policy-issuer})))))

(def fetch-issuer-ar-interceptor
  {:name    ::fetch-issuer-ar
   :request fetch-issuer-ar})



(defmulti ishare->http-request
  :ishare/message-type)

(def ishare-interpreter-interactor
  {:name ::ishare-interpretor-interactor
   :request ishare->http-request})

(def interceptors
  [ishare-interpreter-interactor
   fetch-issuer-ar-interceptor
   throw-on-exceptional-status-code
   log-interceptor
   logging-interceptor
   lens-interceptor
   unsign-token-interceptor
   build-uri-interceptor
   fetch-bearer-token-interceptor
   bearer-token-interceptor
   interceptors/construct-uri
   interceptors/accept-header
   interceptors/query-params
   interceptors/form-params
   json-interceptor ;; should be between decode-body and
   ;; throw-on-exceptional-status-code, so that JSON
   ;; error messages are decoded
   interceptors/decode-body
   interceptors/decompress-body])

(def ^:dynamic http-client nil)

(def timeout-ms 10000)

(def http-client-opts
  {:follow-redirects :normal
   :connect-timeout  timeout-ms
   :request          {:headers {:accept          "*/*"
                                :accept-encoding ["gzip" "deflate"]
                                :user-agent      "clj-ishare-client"}}})

(def default-http-client
  (delay (http/client http-client-opts)))

(defn exec
  [request]
  (http/request (assoc request
                       :client (or http-client @default-http-client)
                       :interceptors interceptors
                       :timeout timeout-ms)))

(defn satellite-request
  [{:ishare/keys [satellite-base-url satellite-id] :as request}]
  {:pre [satellite-base-url satellite-id]}
  (assoc request
         :ishare/base-url    satellite-base-url
         :ishare/server-id   satellite-id))



(defmethod ishare->http-request :access-token
  [{:ishare/keys [client-id path] :as request}]
  {:pre [client-id]}
  (assoc request
         :path          (or path "connect/token")
         :method       :post
         :as           :json
         :ishare/bearer-token nil
         :form-params  {"client_id"             client-id
                        "grant_type"            "client_credentials"
                        "scope"                 "iSHARE" ;; TODO: allow restricting scope?
                        "client_assertion_type" "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
                        "client_assertion"      (jwt/make-client-assertion request)}
         ;; NOTE: body includes expiry information, which we could use
         ;; for automatic caching -- check with iSHARE docs to see if
         ;; that's always available
         :ishare/lens          [:body "access_token"]))

;; Parties is a satellite endpoint; response will be signed by the
;; satellite, and we cannot use `/parties` endpoint to validate the
;; signature of the `/parties` request.

(defmethod ishare->http-request :parties
  [{:ishare/keys [params] :as request}]
  (-> request
      (satellite-request)
      (assoc :method       :get
             :path          "parties"
             :as           :json
             :query-params  params
             :ishare/unsign-token "parties_token"
             ;; NOTE: pagination to be implemented
             :ishare/lens   [:body "parties_token"])))

(defmethod ishare->http-request :party
  [{:ishare/keys [party-id] :as request}]
  (-> request
      (satellite-request)
      (assoc :method       :get
             :path         (str "parties/" party-id)
             :as           :json
             :ishare/unsign-token "party_token"
             :ishare/lens [:body "party_token"])))

(defmethod ishare->http-request :trusted-list
  [request]
  (-> request
      (satellite-request)
      (assoc :method       :get
             :path         "trusted_list"
             :as           :json
             :ishare/unsign-token "trusted_list_token"
             :ishare/lens         [:body "trusted_list_token"])))

(defmethod ishare->http-request :capabilities
  [request]
  (assoc request
         :method       :get
         :path         "capabilities"
         :as           :json
         :ishare/unsign-token "capabilities_token"
         :ishare/lens         [:body "capabilities_token"]))



(defmethod ishare->http-request :delegation
  [{delegation-mask :ishare/params :as request}]
  (assoc request
         :method               :post
         :path                 "delegation"
         :as                   :json
         :json-params          delegation-mask
         :ishare/unsign-token  "delegation_token"
         :ishare/lens          [:body "delegation_token"]))



(comment
  (def client-data
    {:ishare/client-id   "EU.EORI.NLSMARTPHON"
     :ishare/x5c         (x5c "credentials/EU.EORI.NLSMARTPHON.crt")
     :ishare/private-key (private-key "credentials/EU.EORI.NLSMARTPHON.pem")})

  (def client-data
    {:ishare/client-id   "EU.EORI.NLFLEXTRANS"
     :ishare/x5c         (x5c "credentials/EU.EORI.NLFLEXTRANS.crt")
     :ishare/private-key (private-key "credentials/EU.EORI.NLFLEXTRANS.pem")})

  (def ishare-ar-request
    {:ishare/base-url    "https://ar.isharetest.net/"
     :ishare/server-id   "EU.EORI.NL000000004"
     :ishare/client-id   "EU.EORI.NLSMARTPHON"
     :ishare/x5c         (x5c "credentials/EU.EORI.NLSMARTPHON.crt")
     :ishare/private-key (private-key "credentials/EU.EORI.NLSMARTPHON.pem")})

  (def poort8-ar-request
    {:ishare/base-url    "https://tsl-ishare-dataspace-coremanager-preview.azurewebsites.net/api/ishare/"
     :ishare/server-id   "EU.EORI.NLP8TSLAR1"
     :ishare/client-id   "EU.EORI.NLPRECIOUSG"
     :ishare/x5c         (x5c "credentials/EU.EORI.NLPRECIOUSG.crt")
     :ishare/private-key (private-key "credentials/EU.EORI.NLPRECIOUSG.pem")})

  (def delegation-evidence
    {"delegationEvidence"
     {"notBefore"    0
      "notOnOrAfter" 0
      "policyIssuer" "EU.EORI.NLSMARTPHON"
      "target"       {"accessSubject" "EU.EORI.NLPRECIOUSG"}
      "policySets"   [{"policies" [{"rules"  [{"effect" "Permit"}]
                                    "target" {"resource" {"type"        "klantordernummer"
                                                          "identifiers" ["112233"]
                                                          "attributes"  ["*"]}
                                              "actions"  ["BDI.PICKUP"]}}]
                       "target"   {"resource" {"type"        "klantordernummer"
                                               "identifiers" ["112233"]
                                               "attributes"  ["*"]}
                                   "actions"  ["BDI.PICKUP"]
                                   ;; `licenses` is required, but seems
                                   ;; to fit pretty badly, let's go
                                   ;; for "0001" -- "Re-sharing with
                                   ;; Adhering Parties only"
                                   "environment" {"licenses" ["0001"]}}}]}})

  (def delegation-mask
    {:delegationRequest
     {:policyIssuer "EU.EORI.NLSMARTPHON"
      :target       {:accessSubject "EU.EORI.NLPRECIOUSG"}
      :policySets   [{:policies [{:rules  [{:effect "Permit"}]
                                  :target {:resource    {:type        "klantordernummer"
                                                         :identifiers ["112233"]
                                                         :attributes  ["*"]}
                                           :actions     ["BDI.PICKUP"]
                                           :environment {:licenses ["0001"]
                                                         :serviceProviders []}}}]}]}})

  (-> client-data
      (assoc :ishare/satellite-id (System/getenv "SATELLITE_ID"))
      (assoc :ishare/satellite-base-url (System/getenv "SATELLITE_ENDPOINT"))
      (satellite-request)
      (assoc :ishare/message-type :access-token)
      exec
      :ishare/result)

  (-> ishare-ar-request
      (assoc :ishare/message-type :ishare/policy ;; ishare-ar specific call
             :ishare/params delegation-evidence)
      exec
      :ishare/result)

  (-> ishare-ar-request
      (assoc :ishare/message-type :delegation ;; standardized call
             :ishare/params delegation-mask)
      exec
      :ishare/result))
