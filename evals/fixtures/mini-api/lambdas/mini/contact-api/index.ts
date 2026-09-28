// @ts-nocheck
import { ses } from './ses';

export const handler = async (event: { body: string }) => {
  const { email, message } = JSON.parse(event.body);
  await ses.send({ to: email, subject: 'We received your message', text: message });
  return { statusCode: 204, body: '' };
};
