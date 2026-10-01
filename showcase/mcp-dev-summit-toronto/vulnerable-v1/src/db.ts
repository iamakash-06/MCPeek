import pg from "pg";

export const db = new pg.Pool({ connectionString: process.env.DATABASE_URL });

// Called from the search_sessions tool. The injection is one file away from the handler.
export async function findSessions(term: string, track: string) {
  const sql = `SELECT id, title, speaker, room FROM sessions WHERE title ILIKE '%${term}%' AND track = '${track}'`;
  const { rows } = await db.query(sql);
  return rows;
}
