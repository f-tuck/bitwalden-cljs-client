(ns bitwalden-client-lib.core
  (:require
    [cljs.core.async :refer [chan put! <! close!]]
    [bitwalden-client-lib.buffershim :as buffershim]
    ["dht-bencode/lib/bencode" :as bencode]
    [bitwalden-client-lib.crypto :refer [public-key-b58-from-keypair keypair-from-seed-b58 dht-compute-sig]]
    [bitwalden-client-lib.util :refer [random-hex dht-address is-magnet-url magnet-get-infohash magnet-link]]
    [bitwalden-client-lib.rpc :refer [<api <json-rpc refresh-known-nodes]]
    [bitwalden-client-lib.data :refer [make-profile make-json-feed make-post]])
  (:require-macros
    [cljs.core.async.macros :refer [go]]))

(buffershim/do-shim-buffer)

(def profile-namespace "bw.profile")

; test params
; (def node "http://localhost:8923")
; (go (def nodes (<! (refresh-known-nodes))))
; (def node (get nodes 1))
; (def keypair (keypair-from-seed-b58 "H33xgBQj5jTU6bKC5iw6B9docquvNpDeKoSSWkCpcU58"))
; (def pubkey (public-key-b58-from-keypair keypair))

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
; (go (print (<! (profile-fetch (nodes 0) keypair "7Q9he6fH1m6xAk5buSSPwK4Jjmute9FjF5TgidTZqiHM"))))
(defn profile-fetch
  "Fetch account's profile data. Asynchronous."
  [node keypair public-key-base58]
  (<json-rpc node keypair "dht-get" {:addresshash (dht-address public-key-base58 profile-namespace) :salt profile-namespace}))

; update account profile
; (go (print (<! (profile-update! (nodes 0) keypair {:name "Test face" :email "tester@test.com"}))))
(defn profile-update!
  "Update account's profile data. Asynchronous."
  [node keypair datastructure]
  (go
    ; bencode datastructure
    (let [public-key-base58 (public-key-b58-from-keypair keypair)
          datastructure-bencoded (.toString (bencode/bencode (clj->js datastructure)))]
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
; (go (let [c (content-fetch (nodes 0) keypair "448c6cc0e816408859ba8753705c2b2264548fdf")]
;      (loop []
;        (let [r (<! c)]
;          (print "got" r)
;          (if r
;            (recur))))))
(defn content-fetch-from-magnet
  "Fetch some content by hash. Asynchronous."
  [node keypair infohash]
  (let [uid (random-hex 8)
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

(defn content-get-http-url
  "Convert a content URL or regular HTTP URL into an HTTP URL."
  [node keypair url]
  (go (if (is-magnet-url url) (<! (content-fetch-magnet-url node keypair (magnet-get-infohash url))) url)))

; (go (print (get-in (<! (content-get (get nodes 1) keypair "magnet:?xt=urn:btih:9071384156b7d415fa0a1a0dd2f08d0793022c9a")) ["content" "items"])))
(defn content-get
  "Get remote content by URL."
  [node keypair url]
  (go
    (let [actual-url (<! (content-get-http-url node keypair url))
          [code response] (<! (<api :get actual-url))]
      (if (and (= code :ok) response)
        {:content response}
        {:error true :message (str "Problem downloading " url) :code 400 :error-response response}))))

; store content
; (go (print (<! (content-store! (nodes 0) keypair "7Q9he6fH1m6xAk5buSSPwK4Jjmute9FjF5TgidTZqiHM.json" (js/JSON.stringify (clj->js {:version "https://jsonfeed.org/version/1" :title "Testing" :items [1 2 3 "wingwang"]}))))))
(defn content-store!
  "Store some content. Returns the hash. Asynchronous."
  [node keypair content-name content]
  (<json-rpc node keypair "torrent-seed" {:name content-name :content content}))

; get posts
; (go (print (<! (refresh-account (nodes 0) keypair "7Q9he6fH1m6xAk5buSSPwK4Jjmute9FjF5TgidTZqiHM"))))
(defn refresh-account [node keypair public-key-base58]
  (go
    (let [profile (<! (profile-fetch node keypair public-key-base58))
          profile-data (if (and profile (get profile "v")) (into {} (doall (map (fn [[k v]] [k (if v (.toString v))]) (js->clj (bencode/bdecode (profile "v")))))))]
      ; TODO: verify stored sig in "s.dht" field
      (if profile-data
        (if (= (profile-data "pk") public-key-base58)
          (let [feed-url (profile-data "feed-url")
                feed (if feed-url (<! (content-get node keypair feed-url)))]
            {:profile profile-data :feed (if (and feed (not (feed :error)) (feed :content)) (feed :content))})
          {:error true :message "Public key did not match." :code 400})
        {:error true :message "No profile data returned."}))))

; add post
; (go (print (<! (add-post! (nodes 0) keypair (make-post (random-hex 16) "Beep boop. Hello.")))))
(defn add-post! [node keypair post & [profile posts-feed]]
  (go
    (let [public-key-b58 (public-key-b58-from-keypair keypair)
          profile (or profile (make-profile public-key-b58))
          posts-feed (or posts-feed (make-json-feed public-key-b58))
          posts-feed (update-in posts-feed ["items"] #(into [post] %))
          blob (js/JSON.stringify (clj->js posts-feed))
          ; {infohash ...}
          updated-feed (<! (content-store! node keypair (str public-key-b58 ".json") blob))
          infohash (updated-feed "infohash")]
      (if infohash
        (let [magnet-link (magnet-link infohash)
              profile (assoc profile "feed-url" magnet-link)
              ; {addresshash ... nodecount ...}
              update-response (<! (profile-update! node keypair profile))]
          (if (update-response :error)
            update-response
            (if (and (> (update-response "nodecount") 0) (update-response "addresshash"))
              {:profile profile :feed posts-feed}
              update-response)))
        updated-feed))))

