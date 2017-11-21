(ns bitwalden-client-lib.data)

(defn make-profile [public-key-base58]
  {"public-key-base58" public-key-base58})

(defn make-json-feed [public-key-base58]
  {"version" "https://jsonfeed.org/version/1"
   "title" (str public-key-base58 "'s feed")
   "bitwalden" {"public-key-base58" public-key-base58}
   "items" []})

(defn make-post [id content]
  {"id" id
   "content_text" content
   "format" "gfm"})
