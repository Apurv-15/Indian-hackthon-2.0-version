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

    const isPlaceholder = (val) => !val || val.includes('ENTER_') || val.includes('your-email');

    if (isPlaceholder(GMAIL_CLIENT_ID) || isPlaceholder(GMAIL_CLIENT_SECRET) || isPlaceholder(GMAIL_REFRESH_TOKEN) || isPlaceholder(GMAIL_USER_EMAIL)) {
      console.warn('Gmail OAuth environment variables are using placeholders. Falling back to mock data.');
      const mockDetails = [
        {
          id: 'mock-1',
          from: 'Security Alert <security@paypal-security.xyz>',
          subject: 'URGENT: Your PayPal account has been limited',
          snippet: 'Your account has been restricted due to suspicious activity. Click here to verify your identity immediately: http://paypal-security.xyz/verify-account',
          time: new Date().toISOString(),
        },
        {
          id: 'mock-2',
          from: 'HR Support <hr-portal@office-updates.online>',
          subject: 'New Policy: Action Required',
          snippet: 'Please review the new remote work policy by 5 PM today. Access the document here: http://office-updates.online/policy-docs',
          time: new Date(Date.now() - 3600000).toISOString(),
        },
        {
          id: 'mock-3',
          from: 'John Doe <john.doe@gmail.com>',
          subject: 'Meeting Refined',
          snippet: 'Hey, I refined the meeting notes for tomorrow. Let me know if you have any feedback!',
          time: new Date(Date.now() - 7200000).toISOString(),
        },
        {
          id: 'mock-4',
          from: 'Netflix <billing@netf-update.win>',
          subject: 'Payment Declined',
          snippet: 'Your last payment for Netflix was declined. Please update your payment information to avoid service interruption: http://netf-update.win/billing',
          time: new Date(Date.now() - 86400000).toISOString(),
        },
      ];
      return NextResponse.json(mockDetails);
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
        const from = getHeader(headers, 'From') || 'Unknown Sender';
        const subject = getHeader(headers, 'Subject') || '(No Subject)';
        const snippet = msgRes.data.snippet || 'No preview available';
        const time = toIsoTime(msgRes.data.internalDate);

        return {
          id: message.id,
          from,
          subject,
          snippet,
          time,
        };
      })
    );

    return NextResponse.json(details);
  } catch (error) {
    console.error('Gmail API Error. Falling back to mock data:', error.message);
    const mockDetails = [
      {
        id: 'error-fallback-1',
        from: 'System <security@aegis-ai.internal>',
        subject: '[DEMO MODE] Security Analysis Sample 1',
        snippet: 'This is a sample threat detected by our offline analysis engine. Click to view forensic indicators.',
        time: new Date().toISOString(),
      },
      {
        id: 'error-fallback-2',
        from: 'Cyber Intel <intel@threat-feed.com>',
        subject: '[DEMO MODE] Phishing Campaign Detected',
        snippet: 'High risk domain similarity detected in recently intercepted web traffic. Immediate attention recommended.',
        time: new Date(Date.now() - 3600000).toISOString(),
      }
    ];
    return NextResponse.json(mockDetails);
  }
}
