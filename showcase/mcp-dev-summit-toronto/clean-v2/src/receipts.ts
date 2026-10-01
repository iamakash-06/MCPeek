import { SignJWT } from "jose";

// The token carries only an opaque receipt id. Card and payment details stay in the database.
export async function issueReceipt(attendeeEmail: string, receiptId: string) {
  return new SignJWT({ sub: attendeeEmail, rid: receiptId })
    .setProtectedHeader({ alg: "HS256" })
    .setExpirationTime("30d")
    .sign(new TextEncoder().encode(process.env.RECEIPT_KEY!));
}
