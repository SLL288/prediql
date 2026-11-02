import React from "react";
import ReactDOM from "react-dom/client";
import { createBrowserRouter, RouterProvider } from "react-router-dom";
import "./index.css";
import { App } from "./App";
import { ErrorBoundary } from "./components/ErrorBoundary";
import { Overview } from "./pages/Overview";
import { RunDetail } from "./pages/RunDetail";
import { Live } from "./pages/Live";
import { Compare } from "./pages/Compare";
import { Baselines } from "./pages/Baselines";
import { Fuzz4all } from "./pages/Fuzz4all";
import { Reliability } from "./pages/Reliability";
import { Security } from "./pages/Security";
import { Coverage } from "./pages/Coverage";

const router = createBrowserRouter([
  {
    path: "/",
    element: <App />,
    errorElement: <ErrorBoundary />,
    children: [
      { index: true, element: <Overview /> },
      { path: "runs/:runId", element: <RunDetail /> },
      { path: "live", element: <Live /> },
      { path: "compare", element: <Compare /> },
      { path: "baselines", element: <Baselines /> },
      { path: "fuzz4all", element: <Fuzz4all /> },
      { path: "reliability", element: <Reliability /> },
      { path: "security", element: <Security /> },
      { path: "coverage", element: <Coverage /> },
    ],
  },
]);

ReactDOM.createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <RouterProvider router={router} />
  </React.StrictMode>
);
