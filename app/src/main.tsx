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
import { SetupPage } from "./components/Home.tsx";
import { HistoryPage, StoredReviewPage } from "./components/HistoryPages.tsx";
import { ReviewPage } from "./components/ReviewPage.tsx";
import "./styles.css";

/**
 * An address that leads nowhere says so in plain words, with a way back,
 * instead of showing the front page as if it were what was asked for.
 */
function NotFound() {
  return (
    <main className="mx-auto max-w-2xl px-4 py-16">
      <p className="text-lg font-semibold text-ink">ShipBrace</p>
      <h1 className="mt-8 text-xl font-semibold text-ink sm:text-2xl">This page doesn't exist</h1>
      <p className="mt-2 text-sm leading-relaxed text-ink-soft">
        The address may be mistyped, or the report it pointed to may have been deleted.
      </p>
      <a href="/" className="mt-6 inline-block text-sm font-medium text-ink underline">
        Go to the front page
      </a>
    </main>
  );
}

const rootRoute = createRootRoute({ component: () => <Outlet />, notFoundComponent: NotFound });

const reviewRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/",
  component: ReviewPage,
});

// Kept reviews from GitHub pushes, at the addresses the check links to.
const storedReviewRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/reviews/$id",
  component: function StoredReview() {
    return <StoredReviewPage id={storedReviewRoute.useParams().id} />;
  },
});

const historyRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/history/$id",
  component: function History() {
    return <HistoryPage id={historyRoute.useParams().id} />;
  },
});

// GitHub's "Setup URL": where people land after allowing ShipBrace on a repository.
const setupRoute = createRoute({ getParentRoute: () => rootRoute, path: "/setup", component: SetupPage });

const router = createRouter({
  routeTree: rootRoute.addChildren([reviewRoute, storedReviewRoute, historyRoute, setupRoute]),
});

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
