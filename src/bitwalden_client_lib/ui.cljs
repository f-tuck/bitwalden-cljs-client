(ns bitwalden-client-lib.ui
    (:require
      [reagent.core :as r]
      [bitwalden-client-lib.core :as bitwalden]))

;; -------------------------
;; Views

(defn home-page []
  [:div [:h2 "Welcome to Reagent"]])

;; -------------------------
;; Initialize app

(defn mount-root []
  (r/render [home-page] (.getElementById js/document "app")))

(defn init! []
  (mount-root))
