// Negative cases, both of which must NOT produce a candidate:
//  (1) an inline object-literal filter is the `object` arg shape, which the
//      nosql-injection matcher excludes (only the whole-object `other`
//      pass-through fires);
//  (2) `Array.prototype.find(callback)` is the most common reason `*.find` would
//      over-fire. The matcher deliberately drops `*.find` (keeping only
//      Mongo-specific verbs), so an array `.find(predicate)` produces nothing.
interface Users {
  findOne(query: unknown): Promise<unknown>;
}

export async function activeUsers(users: Users): Promise<unknown> {
  return users.findOne({ active: true });
}

export function firstActive(rows: Array<{ active: boolean }>): { active: boolean } | undefined {
  // Array.prototype.find with a callback: classified as the `other` arg shape,
  // must not be mistaken for a Mongo query.
  return rows.find((row) => row.active);
}
