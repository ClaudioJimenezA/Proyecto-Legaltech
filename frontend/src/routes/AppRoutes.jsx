import React from 'react';
import { BrowserRouter, Navigate, Route, Routes } from 'react-router-dom';
import RoeDashboard from '../features/roe_negotiation/components/RoeDashboard';

export default function AppRoutes() {
  return (
    <BrowserRouter>
      <Routes>
        <Route path="/roe" element={<RoeDashboard />} />
        <Route path="/" element={<Navigate to="/roe" replace />} />
        <Route path="*" element={<Navigate to="/roe" replace />} />
      </Routes>
    </BrowserRouter>
  );
}
