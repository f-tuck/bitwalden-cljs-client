(ns bitwalden-client-lib.util
  (:require  [alphabase.base58 :as b58])
  (:import goog.crypt.Sha1
           [goog.async Debouncer]))

(defonce utf8encoder (js/TextEncoder. "utf8"))

(def magnet-prefix "magnet:?xt=urn:btih:")

; --- data format utils --- ;

(defn hexenate [b]
  (.join (.map (js/Array.from (.slice b)) #(.slice (str "0" (.toString (bit-and % 0xff) 16)) -2)) ""))

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

(defn magnet-link [infohash & [filename]]
  (str magnet-prefix infohash (if filename (str "&dn=" filename))))

(defn magnet-get-infohash [url]
  (let [re #"(?i)\bmagnet:.xt=urn:btih:([A-F\d]+)\b"
        m (.exec re url)]
    (and m (.toLowerCase (get m 1)))))

(defn is-magnet-url [url]
  (= (.indexOf url magnet-prefix) 0))

; --- utils --- ;

(defn now []
  (.getTime (js/Date.)))

(defn with-timestamp [params]
  (assoc params :t (now)))

(defn random-hex [len]
  (hexenate (nacl.randomBytes len)))

(defn debounce [f interval]
  (let [dbnc (Debouncer. f interval)]
    ;; We use apply here to support functions of various arities
    (fn [& args] (.apply (.-fire dbnc) dbnc (to-array args)))))

