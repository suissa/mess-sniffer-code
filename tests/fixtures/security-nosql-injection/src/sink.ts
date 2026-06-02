// Positive: passing a whole user-controlled filter object through to a Mongo
// query operator is a NoSQL-injection candidate (CWE-943). The variable can
// carry operators like `{ $where: ... }` from attacker input. `findOne` is a
// Mongo-specific verb (no Array.prototype equivalent), so matching it does not
// collide with array iteration.
interface Users {
  findOne(query: unknown): Promise<unknown>;
}

export async function lookup(users: Users, userQuery: Record<string, unknown>): Promise<unknown> {
  return users.findOne(userQuery);
}
