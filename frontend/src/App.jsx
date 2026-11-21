import React from "react";

import {
  Routes,
  Route
} from "react-router-dom";

import AppLayout from "./layouts/AppLayout";

import Dashboard from "./pages/Dashboard";
import Emails from "./pages/Emails";
import EmailDetails from "./pages/EmailDetails";
import HeaderForensics from "./pages/HeaderForensics";
import Authentication from "./pages/Authentication";
import UrlIntelligence from "./pages/UrlIntelligence";
import ExtendedAnalysis from "./pages/ExtendedAnalysis";
import Alerts from "./pages/Alerts";
import Cases from "./pages/Cases";
import AnalysisHistory from "./pages/AnalysisHistory";
import NotFound from "./pages/NotFound";

export default function App() {
  return (
    <Routes>
      <Route
        element={<AppLayout />}
      >
        <Route
          path="/"
          element={<Dashboard />}
        />

        <Route
          path="/emails"
          element={<Emails />}
        />

        <Route
          path="/emails/:emailId"
          element={<EmailDetails />}
        />

        <Route
          path="/headers"
          element={<HeaderForensics />}
        />

        <Route
          path="/authentication"
          element={<Authentication />}
        />

        <Route
          path="/urls"
          element={<UrlIntelligence />}
        />

        <Route
          path="/extended"
          element={<ExtendedAnalysis />}
        />

        <Route path="/alerts" element={<Alerts />} />

        <Route path="/cases" element={<Cases />} />

        <Route path="/history" element={<AnalysisHistory />} />

        <Route
          path="*"
          element={<NotFound />}
        />
      </Route>
    </Routes>
  );
}
