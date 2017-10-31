(ns bitwalden-client-lib.core
  (:require
    [cljs.core.async :refer [chan put! <!]]
    [ajax.core :refer [GET POST]]
    [cljsjs.nacl-fast :as nacl]
    [alphabase.base58 :as b58]
    [goog.crypt.Sha1 :as Sha1]
    [bencode :as bencode])
  (:require-macros
    [cljs.core.async.macros :refer [go]])
  (:import goog.crypt.Sha1))

(def profile-namespace "bw.profile")

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

(defn <api [method uri & [opts]]
  (let [c (chan)]
    (apply ({:get GET :post POST} method) [uri (assoc opts :handler #(put! c [:ok %]) :error-handler #(put! c [:error %]))])
    c))

(defn <json-rpc [node method params]
  (go (let [[code response] (<! (<api :post (str node "/bw/rpc") {:params {"jsonrpc" "2.0" "method" method "id" (hexenate (nacl.randomBytes 32)) "params" params} :format :json}))]
        ; [:ok {jsonrpc 2.0, id 1, result {pong true, c 12}}]
        (when (and (= code :ok) (response "result"))
          (response "result")))))

(defn dht-address [public-key-b58 salt]
  (let [sha1 (goog.crypt.Sha1.)]
    (.update sha1 (join-uint8arrays (b58/decode public-key-b58) (string-to-uint8array salt)))
    (hexenate (.digest sha1))))

(defn magnet-link [infohash & [filename]]
  (str "magnet:?xt=urn:btih:" infohash (if filename (str "&dn=" filename))))

(defn dht-compute-sig [keypair params]
  (let [params-encoded (js/Bencode.encode (clj->js params))
        sig-unit (.substring params-encoded 1 (- (.-length params-encoded) 1))]
    (hexenate (nacl.sign.detached (string-to-uint8array sig-unit) (.-secretKey keypair)))))

(defn keys-from-secret [secret]
  (.fromSecretKey nacl.sign.keyPair (js/Uint8Array.from secret)))

(defn keys-from-seed [seed]
  (.fromSeed nacl.sign.keyPair (nacl.hash (string-to-uint8array seed))))

(defn pk-from-secret [secret]
  (js/Array.from (.-publicKey (keys-from-secret secret))))

(defn fetch-known-nodes []
  (go
    (let [known-nodes (<! (<api :get "known-nodes.txt"))]
      (when (= (first known-nodes) :ok)
        (vec (remove #(= % "") (.split (second known-nodes) "\n")))))))

(defn refresh-known-nodes [& [known-nodes callback]]
  (go
    ; if we have no known nodes load known-nodes.txt from the server
    (let [known-nodes (if (= (count known-nodes) 0) (<! (fetch-known-nodes)) known-nodes)]
      ; TODO: loop through subset of known nodes querying their peer list
      (if callback (callback known-nodes))
      known-nodes)))

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

; fetch account profile
; (go (print (<! (profile-fetch "http://localhost:8923" (public-key-b58-from-keypair (keypair-from-seed-b58 "H33xgBQj5jTU6bKC5iw6B9docquvNpDeKoSSWkCpcU58"))))))
(defn profile-fetch
  "Fetch account's profile data. Asyncrhonous."
  [node public-key-base58 & [callback]]
  (go
    (let [result (<! (<json-rpc node "dht-get" {:addresshash (dht-address public-key-base58 profile-namespace)}))]
      (if callback (apply callback result))
      result)))

; update account profile
; (go (print (<! (profile-update "http://localhost:8923" (keypair-from-seed-b58 "H33xgBQj5jTU6bKC5iw6B9docquvNpDeKoSSWkCpcU58") {:name "Test face" :email "tester@test.com"}))))
(defn profile-update
  "Update account's profile data. Asynchronous."
  [node keypair datastructure & [callback]]
  (go
    ; bencode datastructure
    (let [public-key-base58 (public-key-b58-from-keypair keypair)
          datastructure-bencoded (js/Bencode.encode (clj->js datastructure))]
      ; check size < 1000 bytes
      (if (>= (.-length datastructure-bencoded) 1000)
        ["Profile data too large." nil]
        ; generate signed packet
        (let [; get previous value
              [err response] (<! (<json-rpc node "dht-get" {:addresshash (dht-address public-key-base58 profile-namespace)}))
              dht-params {:v datastructure-bencoded :seq (if response (inc (response "seq")) 1) :salt profile-namespace}
              sig (dht-compute-sig keypair dht-params)
              post-data (merge dht-params {:k public-key-base58 :s.dht sig})
              ; post to nodes
              response (<! (<json-rpc node "dht-put" post-data))
              [err dht-hash node-count] response]
          (if callback (callback err dht-hash node-count))
          response)))))

; fetch content
; (go (let [c (content-fetch "http://45.32.253.186:8923" "448c6cc0e816408859ba8753705c2b2264548fdf")]
;      (loop []
;        (let [r (<! c)]
;          (print "got" r)
;          (if r
;            (recur))))))
(defn content-fetch
  "Fetch some content by hash. Asynchronous."
  [node infohash & [callback]]
  (let [uid (hexenate (nacl.randomBytes 8))
        c (chan)]
    (print uid c)
    (let [new-uid (<! (<json-rpc node "torrent-fetch" {:infohash infohash :u uid}))]
      (print new-uid)
      (if new-uid
        (print "new-uid" new-uid)
        (loop [after 0]
          (let [update (<! (<json-rpc node "get-queue" {:u new-uid :after after}))
                latest-timestamp (apply js/Math.max (map #(get % "timestamp") update))]
            (print update)
            (for [u update]
              (if callback
                (callback nil (u "payload"))
                (put! c [nil (u "payload")])))
            (when update (recur latest-timestamp)))))
      (if callback (callback nil new-uid))
      (put! c [nil new-uid]))
    c))

; store content
; (go (print (<! (content-store "http://localhost:8923" "7Q9he6fH1m6xAk5buSSPwK4Jjmute9FjF5TgidTZqiHM.json" (js/JSON.stringify (clj->js {:version "https://jsonfeed.org/version/1" :title "Testing" :items []}))))))
(defn content-store
  "Store some content. Returns the hash. Asynchronous."
  [node content-name content & [callback]]
  (go
    (let [[err infohash] (<! (<json-rpc node "torrent-seed" {:name content-name :content content}))]
      (if callback (callback err infohash))
      [err infohash])))

; get posts

; add post

