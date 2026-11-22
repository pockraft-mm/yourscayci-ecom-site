import { handleRequest } from '../dist-server/server/index.js';

export default function handler(req, res) {
  return handleRequest(req, res);
}
