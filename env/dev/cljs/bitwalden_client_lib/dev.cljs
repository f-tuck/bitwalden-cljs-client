(ns ^:figwheel-no-load bitwalden-client-lib.dev
  (:require
    [bitwalden-client-lib.ui :as ui]
    [devtools.core :as devtools]))


(enable-console-print!)

(devtools/install!)

(ui/init!)
