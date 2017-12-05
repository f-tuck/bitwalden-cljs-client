(ns bitwalden-client-lib.buffershim
  (:require ["buffer/index" :as buffer :refer [Buffer]]))

(defn do-shim-buffer []
  (aset js/window "Buffer" Buffer))

(do-shim-buffer)
