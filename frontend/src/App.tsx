import { Navigate, Route, Routes } from "react-router-dom";
import { Layout } from "./components/Layout";
import { AboutPage } from "./pages/About";
import { DashboardPage } from "./pages/Dashboard";
import { FindingDetailPage } from "./pages/FindingDetail";
import { FindingsPage } from "./pages/Findings";
import { HistoryPage } from "./pages/History";
import { NewScanPage } from "./pages/NewScan";
import { ReportsPage } from "./pages/Reports";
import { SettingsPage } from "./pages/Settings";

export default function App() {
  return (
    <Routes>
      <Route element={<Layout />}>
        <Route path="/" element={<DashboardPage />} />
        <Route path="/scan" element={<NewScanPage />} />
        <Route path="/findings" element={<FindingsPage />} />
        <Route path="/findings/:id" element={<FindingDetailPage />} />
        <Route path="/history" element={<HistoryPage />} />
        <Route path="/reports" element={<ReportsPage />} />
        <Route path="/settings" element={<SettingsPage />} />
        <Route path="/about" element={<AboutPage />} />
        <Route path="*" element={<Navigate to="/" replace />} />
      </Route>
    </Routes>
  );
}
