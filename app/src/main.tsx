import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import {
  createRootRoute,
  createRoute,
  createRouter,
  Outlet,
  RouterProvider,
} from "@tanstack/react-router";
import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { ReviewPage } from "./components/ReviewPage.tsx";
import "./styles.css";

const rootRoute = createRootRoute({ component: () => <Outlet /> });

const reviewRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/",
  component: ReviewPage,
});

const router = createRouter({ routeTree: rootRoute.addChildren([reviewRoute]) });

declare module "@tanstack/react-router" {
  interface Register {
    router: typeof router;
  }
}

// A failed review must never look like a passed one, so it is not retried into
// a silent empty state -- the page shows an explicit error instead.
const queryClient = new QueryClient({
  defaultOptions: { queries: { retry: 1, refetchOnWindowFocus: false } },
});

const root = document.getElementById("root");
if (!root) throw new Error("Missing #root element");

createRoot(root).render(
  <StrictMode>
    <QueryClientProvider client={queryClient}>
      <RouterProvider router={router} />
    </QueryClientProvider>
  </StrictMode>,
);
