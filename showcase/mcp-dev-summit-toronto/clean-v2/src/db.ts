import pg from "pg";

export const db = new pg.Pool({ connectionString: process.env.DATABASE_URL });

// Values travel as bind parameters, never inside the SQL text.
export async function findSessions(term: string, track: string) {
  const { rows } = await db.query(
    "SELECT id, title, speaker, room FROM sessions WHERE title ILIKE $1 AND track = $2",
    [`%${term}%`, track]
  );
  return rows;
}
