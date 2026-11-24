import React from "react";
import ReactDOM from "react-dom/client";
import App from "./App";
import { UrlPickerWindow } from "./components/UrlPickerWindow";
import "./styles.css";

interface TauriWindowInternals {
  __TAURI_INTERNALS__?: {
    metadata?: {
      currentWindow?: {
        label?: string;
      };
    };
  };
}

function detectUrlPickerMode(): boolean {
  if (typeof window === "undefined") {
    return false;
  }
  if (new URLSearchParams(window.location.search).get("mode") === "url-picker") {
    return true;
  }
  const internals = (window as unknown as TauriWindowInternals).__TAURI_INTERNALS__;
  return internals?.metadata?.currentWindow?.label === "url-picker";
}

const isUrlPickerMode = detectUrlPickerMode();

ReactDOM.createRoot(document.getElementById("root") as HTMLElement).render(
  <React.StrictMode>
    {isUrlPickerMode ? <UrlPickerWindow /> : <App />}
  </React.StrictMode>,
);
