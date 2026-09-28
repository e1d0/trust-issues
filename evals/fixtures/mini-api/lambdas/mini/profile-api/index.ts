// @ts-nocheck
import { log } from './log';
import { customers } from './customers';

export const handler = async (event: { headers: Record<string, string>; requestContext: { authorizer: { customerId: string } } }) => {
  log.info('profile request', { headers: event.headers });
  const profile = await customers.get(event.requestContext.authorizer.customerId);
  return { statusCode: 200, body: JSON.stringify({ firstName: profile.firstName, lastName: profile.lastName }) };
};
