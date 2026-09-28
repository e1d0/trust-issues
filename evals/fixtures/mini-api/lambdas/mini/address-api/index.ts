// @ts-nocheck
import { addresses } from './addresses';

export const handler = async (event: { pathParameters: { addressId: string }; requestContext: { authorizer: { customerId: string } } }) => {
  const address = await addresses.get(event.pathParameters.addressId);
  if (!address || address.customerId !== event.requestContext.authorizer.customerId) {
    return { statusCode: 404, body: '' };
  }
  return { statusCode: 200, body: JSON.stringify({ city: address.city, postalCode: address.postalCode }) };
};
