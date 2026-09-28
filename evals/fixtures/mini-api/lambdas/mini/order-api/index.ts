// @ts-nocheck
import { ordersClient } from './orders-client';

export const handler = async (event: { pathParameters: { orderId: string }; requestContext: { authorizer: { customerId: string } } }) => {
  const order = await ordersClient.getById(event.pathParameters.orderId);
  if (!order) return { statusCode: 404, body: '' };
  return { statusCode: 200, body: JSON.stringify(order) };
};
