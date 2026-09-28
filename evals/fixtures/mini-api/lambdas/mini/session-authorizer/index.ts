// @ts-nocheck
import { sessionStore } from './session-store';

export const handler = async (event: { headers?: Record<string, string> }) => {
  const cookie = event.headers?.Cookie ?? event.headers?.cookie;
  const session = cookie ? await sessionStore.fromCookie(cookie) : undefined;
  const effect = session ? 'Allow' : 'Deny';
  return {
    principalId: 'user',
    context: { customerId: session?.customerId },
    policyDocument: {
      Version: '2012-10-17',
      Statement: [{ Action: 'execute-api:Invoke', Effect: effect, Resource: 'arn:aws:execute-api:*:*:*' }],
    },
  };
};
