import { Request, Response } from 'express';
import { db } from './db';

interface Note {
  id: string;
  userId: string;
  content: string;
  timestamp: number;
}

const notes: Note[] = [];

export function getProfileService(req: Request, res: Response) {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Missing or invalid Authorization header' });
  }

  const token = authHeader.substring(7);
  const tokenRecord = db.getTokenByAccessToken(token);
  if (!tokenRecord) {
    return res.status(401).json({ error: 'Access token expired or invalid' });
  }

  const user = db.getUserById(tokenRecord.userId);
  if (!user) {
    return res.status(404).json({ error: 'User not found' });
  }

  const userCredentials = db.getCredentialsByUserId(user.id);
  const userNotes = notes.filter(n => n.userId === user.id);

  return res.json({
    status: 'success',
    message: `Welcome back, ${user.displayName}! You have accessed the protected mock service.`,
    user: {
      id: user.id,
      username: user.username,
      displayName: user.displayName,
      createdAt: user.createdAt,
    },
    credentials: userCredentials.map(c => ({
      id: c.id,
      type: c.credentialType,
      aaguid: c.aaguid,
      backupEligible: c.backupEligible,
      backupState: c.backupState,
      userVerified: c.userVerified,
      createdAt: c.createdAt,
    })),
    notesCount: userNotes.length,
    timestamp: Date.now(),
  });
}

export function createNoteService(req: Request, res: Response) {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Missing or invalid Authorization header' });
  }

  const token = authHeader.substring(7);
  const tokenRecord = db.getTokenByAccessToken(token);
  if (!tokenRecord) {
    return res.status(401).json({ error: 'Access token expired or invalid' });
  }

  const { content } = req.body;
  if (!content) {
    return res.status(400).json({ error: 'Note content is required' });
  }

  const note: Note = {
    id: 'note_' + Math.random().toString(36).substring(2, 9),
    userId: tokenRecord.userId,
    content,
    timestamp: Date.now(),
  };
  notes.push(note);

  return res.json({ status: 'success', note });
}
