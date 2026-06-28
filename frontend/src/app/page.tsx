/**
 * Dashboard page — entry point for the Next.js app.
 * Replace the placeholder components below with your v0-scaffolded UI.
 * Each section maps 1:1 to the previous Streamlit pages.
 */
export default function DashboardPage() {
  return (
    <main className="min-h-screen bg-[#0a0f1a] text-slate-200 p-8">
      <h1 className="text-2xl font-bold text-cyan-400 mb-6">ReconIQ Dashboard</h1>
      <p className="text-slate-400">
        Use <code className="text-cyan-400">v0.dev</code> to scaffold the dashboard
        component here. Wire it to <code>getHistory()</code> from{" "}
        <code>@/lib/api</code>.
      </p>
    </main>
  );
}
