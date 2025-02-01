import { Routes, Route } from 'react-router-dom';
import ProtectedRoute from './components/ProtectedRoute';
import { PERMISSIONS } from '../config/roles';

function App() {
  return (
    <Routes>
      <Route path="/login" element={<Login />} />
      <Route path="/register" element={<Register />} />
      
      <Route path="/admin/users" element={
        <ProtectedRoute 
          requiredRole="admin"
          requiredPermission={PERMISSIONS.VIEW_USERS}
        >
          <AdminDashboard />
        </ProtectedRoute>
      } />

      <Route path="/vendor/venues" element={
        <ProtectedRoute 
          requiredRole="vendor"
          requiredPermission={PERMISSIONS.MANAGE_VENUES}
        >
          <VendorDashboard />
        </ProtectedRoute>
      } />

      {/* ... other routes ... */}
    </Routes>
  );
}

export default App; 