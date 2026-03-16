import { google } from 'googleapis';
import { NextResponse } from 'next/server';

export const dynamic = 'force-dynamic';

function getHeader(headers, name) {
  const found = headers?.find(h => h.name?.toLowerCase() === name.toLowerCase());
  return found?.value || '';
}

function toIsoTime(internalDate) {
  const parsed = Number(internalDate);
  if (Number.isNaN(parsed) || parsed <= 0) {
    return new Date().toISOString();
  }
  return new Date(parsed).toISOString();
}

export async function GET() {
  try {
    const {
      GMAIL_CLIENT_ID,
      GMAIL_CLIENT_SECRET,
      GMAIL_REDIRECT_URI,
      GMAIL_REFRESH_TOKEN,
      GMAIL_USER_EMAIL,
    } = process.env;

    if (!GMAIL_CLIENT_ID || !GMAIL_CLIENT_SECRET || !GMAIL_REDIRECT_URI || !GMAIL_REFRESH_TOKEN || !GMAIL_USER_EMAIL) {
      return NextResponse.json(
        {
          error: 'Missing Gmail OAuth environment variables.',
          required: [
            'GMAIL_CLIENT_ID',
            'GMAIL_CLIENT_SECRET',
            'GMAIL_REDIRECT_URI',
            'GMAIL_REFRESH_TOKEN',
            'GMAIL_USER_EMAIL',
          ],
        },
        { status: 500 }
      );
    }

    const oauth2Client = new google.auth.OAuth2(
      GMAIL_CLIENT_ID,
      GMAIL_CLIENT_SECRET,
      GMAIL_REDIRECT_URI
    );

    oauth2Client.setCredentials({
      refresh_token: GMAIL_REFRESH_TOKEN,
    });

    const gmail = google.gmail({
      version: 'v1',
      auth: oauth2Client,
    });

    const listRes = await gmail.users.messages.list({
      userId: GMAIL_USER_EMAIL,
      maxResults: 10,
      q: 'in:inbox',
    });

    const messages = listRes.data.messages || [];

    const details = await Promise.all(
      messages.map(async message => {
        const msgRes = await gmail.users.messages.get({
          userId: GMAIL_USER_EMAIL,
          id: message.id,
          format: 'metadata',
          metadataHeaders: ['From', 'Subject', 'Date'],
        });

        const payload = msgRes.data.payload || {};
        const headers = payload.headers || [];

        return {
          from: getHeader(headers, 'From') || 'Unknown Sender',
          subject: getHeader(headers, 'Subject') || '(No Subject)',
          snippet: msgRes.data.snippet || 'No preview available',
          time: toIsoTime(msgRes.data.internalDate),
        };
      })
    );

    return NextResponse.json(details);
  } catch (error) {
    console.error('Gmail fetch error:', error);
    return NextResponse.json(
      {
        error: 'Failed to fetch emails from Gmail API.',
        details: error?.message || 'Unknown error',
      },
      { status: 500 }
    );
  }
}
