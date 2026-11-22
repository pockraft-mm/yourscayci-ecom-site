declare module 'pg' {
  type QueryResult = { rows: any[] };
  type Client = { query(text: string, values?: unknown[]): Promise<QueryResult>; release(): void };
  class Pool { constructor(config: { connectionString?: string; max?: number; ssl?: { rejectUnauthorized: boolean } }); query(text: string, values?: unknown[]): Promise<QueryResult>; connect(): Promise<Client>; }
  const pg: { Pool: typeof Pool };
  export default pg;
}
