import { useRouteError, Link } from "react-router-dom";

/**
 * Route-level error screen.
 *
 * React Router's default is a bare "Unexpected Application Error!" with a stack,
 * which tells an operator nothing actionable. The most common cause here is a
 * version skew — a browser holding a new bundle while the backend process still
 * runs older code — so the page says that plainly and offers the two fixes.
 */
export function ErrorBoundary() {
  const error = useRouteError() as Error | undefined;
  return (
    <div className="mx-auto max-w-2xl px-6 py-16">
      <div className="panel p-6">
        <h1 className="text-lg font-semibold text-fail">This page failed to render</h1>
        <p className="mt-2 text-sm text-dim">
          Most often this is a version skew: the browser is running a freshly built
          UI while the API process still runs older code, so a field the UI expects
          is missing from the response.
        </p>
        <ol className="mt-3 list-decimal space-y-1 pl-5 text-sm text-dim">
          <li>Restart the backend (<code className="code">./dashboard/dev.sh</code>), which rebuilds the UI and reloads the API.</li>
          <li>Hard-refresh this page to drop the cached bundle.</li>
        </ol>
        {error?.message && (
          <pre className="pre mt-4">{error.message}</pre>
        )}
        <Link to="/" className="btn mt-4 inline-flex">Back to Experiments</Link>
      </div>
    </div>
  );
}
