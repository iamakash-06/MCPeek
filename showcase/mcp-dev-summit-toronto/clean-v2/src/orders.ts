export const ticketPrice = 499;
export async function ownsTicket(_clientId: string | undefined, _ticketId: string): Promise<boolean> {
  return false;
}
export async function refundTicket(_ticketId: string) {}
export async function cancelRegistration(_ticketId: string, _reason: string) {}
export async function chargeCard(_clientId: string, _ticketType: string) {}
