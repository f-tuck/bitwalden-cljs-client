(ns bitwalden-client-lib.rpc
  (:require 
    [bitwalden-client-lib.crypto :refer [public-key-b58-from-keypair with-signature dht-compute-sig]]
    [bitwalden-client-lib.util :refer [with-timestamp random-hex]]
    [cljs.core.async :refer [chan put! <! close!]]
    [ajax.core :refer [GET POST]])
  (:require-macros [cljs.core.async.macros :refer [go]]))

; --- API helpers --- ;

(defn <api [method uri & [opts]]
  (let [c (chan)]
    (apply ({:get GET :post POST} method) [uri (assoc opts :handler #(put! c [:ok %]) :error-handler #(put! c [:error %]))])
    c))

(defn <json-rpc [node keypair method params]
  (go (let [signed-timestamped-params (with-signature keypair (with-timestamp (merge params {:k (public-key-b58-from-keypair keypair)})))
            [code response] (<! (<api :post (str node "/bw/rpc") {:params {"jsonrpc" "2.0" "method" method "id" (random-hex 32) "params" signed-timestamped-params} :format :json}))]
        ; [:ok {jsonrpc 2.0, id 1, result {pong true, c 12}}]
        (if (and (= code :ok) (response "result"))
          (response "result")
          (assoc response :error true)))))

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

