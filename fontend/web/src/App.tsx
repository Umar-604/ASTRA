import { RouterProvider } from 'react-router-dom';
import { appRouter } from '@routes/AppRoutes';
import { ErrorBoundary } from '@components/system/ErrorBoundary';

export function App() {
  return (
    <ErrorBoundary>
      <RouterProvider router={appRouter} />
    </ErrorBoundary>
  );
}
