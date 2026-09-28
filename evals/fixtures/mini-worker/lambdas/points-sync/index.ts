// @ts-nocheck
import { db } from './db';
import { points } from './points';

type PartnerEvent = { eventId: string; customerNumber: string; points: number; country: string };

export const handler = async (event: { Records: { body: string }[] }) => {
  for (const record of event.Records) {
    const e: PartnerEvent = JSON.parse(record.body);
    if (!/^[A-Z]{2}$/.test(e.country)) continue;
    const customer = await db.query(`SELECT id FROM customers WHERE customer_number = '${e.customerNumber}' AND country = '${e.country}'`);
    await points.book(customer.id, e.points);
  }
};
