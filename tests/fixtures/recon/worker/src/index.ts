// Fixture for recon tests. Not real code.
export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);
    if (url.pathname.startsWith('/public/')) {
      return fetch(`${env.UPSTREAM_URL}${url.pathname}`);
    }
    const jwt = request.headers.get('Cf-Access-Jwt-Assertion');
    if (url.pathname === '/orders') {
      return env.ORDERS.fetch(request);
    }
    const session = await env.SESSIONS.get(jwt ?? '');
    return new Response(session ?? 'no session');
  },
  async scheduled(event: ScheduledEvent, env: Env) {
    await env.SESSIONS.delete('expired');
  },
};
