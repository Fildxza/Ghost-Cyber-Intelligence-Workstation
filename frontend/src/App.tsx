import { Navigate, Route, Routes } from "react-router-dom";
import Shell from "./Shell";
import Command from "./pages/Command";
import Operations from "./pages/Operations";
import { CaseDetail, CaseList } from "./pages/Cases";
import Osint from "./pages/Osint";
import Intel from "./pages/Intel";
import Network from "./pages/Network";
import Graph from "./pages/Graph";
import Evidence from "./pages/Evidence";
import Reports from "./pages/Reports";
import Toolkit from "./pages/Toolkit";
import Settings from "./pages/Settings";

export default function App() {
  return (
    <Routes>
      <Route element={<Shell />}>
        <Route index element={<Command />} />
        <Route path="operations" element={<Operations />} />
        <Route path="cases" element={<CaseList />} />
        <Route path="cases/:id" element={<CaseDetail />} />
        <Route path="osint" element={<Osint />} />
        <Route path="intel" element={<Intel />} />
        <Route path="network" element={<Network />} />
        <Route path="graph" element={<Graph />} />
        <Route path="evidence" element={<Evidence />} />
        <Route path="reports" element={<Reports />} />
        <Route path="toolkit" element={<Toolkit />} />
        <Route path="settings" element={<Settings />} />
        <Route path="*" element={<Navigate to="/" replace />} />
      </Route>
    </Routes>
  );
}
