import "@mantine/core/styles.css";
import "@mantine/notifications/styles.css";
import "leaflet/dist/leaflet.css";
import ReactDOM from "react-dom/client";
import { App } from "./app";
import "./styles.css";

const root = document.getElementById("app-root");

if (root) {
  ReactDOM.createRoot(root).render(<App />);
}
