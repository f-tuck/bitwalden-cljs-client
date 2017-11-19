(ns bitwalden-client-lib.core
  (:require
    [cljs.core.async :refer [chan put! <! close!]]
    [ajax.core :refer [GET POST]]
    [cljsjs.nacl-fast :as nacl]
    [alphabase.base58 :as b58]
    [goog.crypt.Sha1 :as Sha1]
    [bencode :as bencode])
  (:require-macros
    [cljs.core.async.macros :refer [go]])
  (:import goog.crypt.Sha1))

(def profile-namespace "bw.profile")

; test params
; (def node "http://localhost:8923")
; (go (def nodes (<! (refresh-known-nodes))))
; (def node (get nodes 1))
; (def keypair (keypair-from-seed-b58 "H33xgBQj5jTU6bKC5iw6B9docquvNpDeKoSSWkCpcU58"))
; (def pubkey (public-key-b58-from-keypair keypair))

; --- utils --- ;

(defn with-timestamp [params]
  (assoc params :t (.getTime (js/Date.))))

; --- data format utils --- ;

(defn hexenate [b]
  (.join (.map (js/Array.from (.slice b)) #(.slice (str "0" (.toString (bit-and % 0xff) 16)) -2)) ""))

(defonce utf8encoder (js/TextEncoder. "utf8"))

(defn string-to-uint8array [s]
  (if (= (type s) js/Uint8Array)
    s
    (.encode utf8encoder s)))

(defn join-uint8arrays [a b]
  (let [n (js/Uint8Array. (+ (.-length a) (.-length b)))]
    (.set n a)
    (.set n b (.-length a))
    n))

(defn dht-address [public-key-b58 salt]
  (let [sha1 (goog.crypt.Sha1.)]
    (.update sha1 (join-uint8arrays (b58/decode public-key-b58) (string-to-uint8array salt)))
    (hexenate (.digest sha1))))

(def magnet-prefix "magnet:?xt=urn:btih:")

(defn magnet-link [infohash & [filename]]
  (str magnet-prefix infohash (if filename (str "&dn=" filename))))

(defn magnet-get-infohash [url]
  (let [re #"(?i)\bmagnet:.xt=urn:btih:([A-F\d]+)\b"
        m (.exec re url)]
    (and m (.toLowerCase (get m 1)))))

; --- key management --- ;

(defn keys-from-secret [secret]
  (.fromSecretKey nacl.sign.keyPair (js/Uint8Array.from secret)))

(defn keys-from-seed [seed]
  (.fromSeed nacl.sign.keyPair (nacl.hash (string-to-uint8array seed))))

(defn pk-from-secret [secret]
  (js/Array.from (.-publicKey (keys-from-secret secret))))

(defn keypair-human-readable [k]
  {:publicKey (b58/encode (.-publicKey k))
   :secretKey (hexenate (.-secretKey k))})

(defn public-key-b58-from-keypair [keypair]
  (b58/encode (.-publicKey keypair)))

(defn keypair-from-seed-phrase [seed-phrase]
  "Deterministic keypair from the first half of the hash of a phrase."
  (-> seed-phrase
      (string-to-uint8array)
      (nacl.hash)
      (.slice 0 32)
      (nacl.sign.keyPair.fromSeed)))

(defn keypair-from-seed-b58 [seed-b58]
  "Deterministic keypair from a b58 encoded 32 byte seed."
  (-> seed-b58
      (b58/decode)
      (.slice 0 32)
      (nacl.sign.keyPair.fromSeed)))

; --- crypto helpers --- ;

(defn dht-compute-sig [keypair params]
  (let [params-encoded (js/Bencode.encode (clj->js params))
        sig-unit (.substring params-encoded 1 (- (.-length params-encoded) 1))]
    (hexenate (nacl.sign.detached (string-to-uint8array sig-unit) (.-secretKey keypair)))))

(defn with-signature [keypair params]
  (let [params-encoded (js/Bencode.encode (clj->js params))
        signature (hexenate (nacl.sign.detached (string-to-uint8array params-encoded) (.-secretKey keypair)))]
    (assoc params :s signature)))

; --- API helpers --- ;

(defn <api [method uri & [opts]]
  (let [c (chan)]
    (apply ({:get GET :post POST} method) [uri (assoc opts :handler #(put! c [:ok %]) :error-handler #(put! c [:error %]))])
    c))

(defn <json-rpc [node keypair method params]
  (go (let [signed-timestamped-params (with-signature keypair (with-timestamp (merge params {:k (public-key-b58-from-keypair keypair)})))
            [code response] (<! (<api :post (str node "/bw/rpc") {:params {"jsonrpc" "2.0" "method" method "id" (hexenate (nacl.randomBytes 32)) "params" signed-timestamped-params} :format :json}))]
        ; [:ok {jsonrpc 2.0, id 1, result {pong true, c 12}}]
        (when (and (= code :ok) (response "result"))
          (response "result")))))

(defn fetch-known-nodes []
  (go
    (let [known-nodes (<! (<api :get "known-nodes.txt"))]
      (when (= (first known-nodes) :ok)
        (vec (remove #(= % "") (.split (second known-nodes) "\n")))))))

; (go (def nodes (<! (refresh-known-nodes))))
(defn refresh-known-nodes [& [known-nodes]]
  (go
    ; if we have no known nodes load known-nodes.txt from the server
    ; TODO: loop through random subset of known nodes querying their peer list
    (if (= (count known-nodes) 0) (<! (fetch-known-nodes)) known-nodes)))

; --- API calls --- ;

(defn make-account
  "Creates a new identity by encrypting a seed with a password. Returns encrypted seed. Use (decrypt-account-keys encrypted-seed password) to obtain the key pair."
  [password & [seed]]
  ; pick random seed if not supplied
  ; generate random salt
  ; scrypt password + salt
  ; generate random nonce
  ; use result to nacl.secretbox seed
  ; return salt + nonce + box
  )

(defn decrypt-account-keys
  "Decrypts seed using password and returns account keys {publicKey: ..., secretKey: ...}."
  [encrypted-seed password]
  ; extract salt from seed
  ; script password + salt to generate box key
  ; extract nonce from seed
  ; nacl.secretbox decrypt seed using key
  ; use seed to generate nacl keypair
  ; return keypair
  )

; fetch account profile
; (go (print (<! (profile-fetch node keypair "7Q9he6fH1m6xAk5buSSPwK4Jjmute9FjF5TgidTZqiHM"))))
(defn profile-fetch
  "Fetch account's profile data. Asynchronous."
  [node keypair public-key-base58]
  (<json-rpc node keypair "dht-get" {:addresshash (dht-address public-key-base58 profile-namespace) :salt profile-namespace}))

; update account profile
; (go (print (<! (profile-update node keypair {:name "Test face" :email "tester@test.com"}))))
(defn profile-update
  "Update account's profile data. Asynchronous."
  [node keypair datastructure]
  (go
    ; bencode datastructure
    (let [public-key-base58 (public-key-b58-from-keypair keypair)
          datastructure-bencoded (js/Bencode.encode (clj->js datastructure))]
      ; check size < 1000 bytes
      (if (>= (.-length datastructure-bencoded) 1000)
        {:error true :message "Profile data too large." :code 400}
        ; generate signed packet
        (let [; get previous value
              dht-get-params {:addresshash (dht-address public-key-base58 profile-namespace) :salt profile-namespace}
              result (<! (<json-rpc node keypair "dht-get" dht-get-params))
              dht-params {:v datastructure-bencoded :seq (if result (inc (result "seq")) 1) :salt profile-namespace}
              sig (dht-compute-sig keypair dht-params)
              post-data (merge dht-params {:k public-key-base58 :s.dht sig})
              ; post to nodes
              response (<! (<json-rpc node keypair "dht-put" post-data))]
          response)))))

; fetch content
; (go (let [c (content-fetch node keypair "448c6cc0e816408859ba8753705c2b2264548fdf")]
;      (loop []
;        (let [r (<! c)]
;          (print "got" r)
;          (if r
;            (recur))))))
(defn content-fetch-from-magnet
  "Fetch some content by hash. Asynchronous."
  [node keypair infohash]
  (let [uid (hexenate (nacl.randomBytes 8))
        c (chan)]
    (go
      (let [new-uid (<! (<json-rpc node keypair "torrent-fetch" {:infohash infohash :u uid}))]
        (when new-uid
          (put! c {"uid" new-uid})
          (loop [after 0]
            (let [update (<! (<json-rpc node keypair "get-queue" {:u new-uid :after after}))
                  latest-timestamp (apply js/Math.max (map #(get % "timestamp") update))
                  files (some identity (doall (for [u update]
                                                (do
                                                  (put! c (assoc (u "payload") "uid" new-uid "timestamp" (u "timestamp")))
                                                  (when (= (get-in u ["payload" "download"]) "done")
                                                    (get-in u ["payload" "files"]))))))
                  done? (or (not update) files)]
              (if done?
                (do
                  (when files
                    (put! c {"uid" new-uid "url" (str node "/bw/content/" infohash "/" (get-in files [0 "path"]))}))
                  (close! c))
                (recur latest-timestamp)))))))
    c))

(defn content-fetch-magnet-url
  "Wait for the remote download of content to finish and return the URL."
  [node keypair infohash]
  (go (let [c (content-fetch-from-magnet node keypair infohash)]
        (loop [url nil]
          (let [r (<! c)
                new-url (or url (r "url"))]
            (if r
              (recur new-url)
              new-url))))))

; (go (print (get-in (<! (content-get (get nodes 1) keypair "magnet:?xt=urn:btih:9071384156b7d415fa0a1a0dd2f08d0793022c9a")) ["content" "items"])))
(defn content-get
  "Get remote content by URL."
  [node keypair url]
  (go
    (let [actual-url (if (= (.indexOf url magnet-prefix) 0) (<! (content-fetch-magnet-url node keypair (magnet-get-infohash url))) url)
          [code response] (<! (<api :get actual-url))]
      (if (and (= code :ok) response)
        {"content" response}
        {:error true :message (str "Problem downloading " url) :code 400}))))

; store content
; (go (print (<! (content-store (nodes 0) keypair "7Q9he6fH1m6xAk5buSSPwK4Jjmute9FjF5TgidTZqiHM.json" (js/JSON.stringify (clj->js {:version "https://jsonfeed.org/version/1" :title "Testing" :items [1 2 3 "wingwang"]}))))))
(defn content-store
  "Store some content. Returns the hash. Asynchronous."
  [node keypair content-name content]
  (<json-rpc node keypair "torrent-seed" {:name content-name :content content}))

; get posts
; add post

