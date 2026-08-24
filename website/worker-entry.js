import application from './index.js';

const responseHeaders = {
  'Permissions-Policy': 'camera=(), microphone=(), geolocation=(), payment=(), usb=()',
  'Referrer-Policy': 'strict-origin-when-cross-origin',
  'X-Content-Type-Options': 'nosniff',
  'X-Frame-Options': 'DENY',
};

const worker = {
  async fetch(request, environment, context) {
    const response = await application.fetch(request, environment, context);
    const headers = new Headers(response.headers);

    for (const [name, value] of Object.entries(responseHeaders)) {
      headers.set(name, value);
    }

    return new Response(response.body, {
      status: response.status,
      statusText: response.statusText,
      headers,
    });
  },
};

export default worker;
