import re
from urllib.parse import urlparse

class TextPreprocessor:
    def __init__(self):
        # Common TLDs or domain pattern for naked URL extraction
        self.naked_domain_pattern = re.compile(
            r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}(?:/[^\s]*)?$'
        )

    def clean_text(self, text):
        """Basic text cleaning"""
        text = ' '.join(text.split())
        return text

    def extract_urls(self, text):
        """Extract URLs from text, supporting both standard http(s) and naked domains."""
        url_pattern = r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'
        urls = re.findall(url_pattern, text)

        # If no standard URL found, check if the input itself or a token is a naked domain
        if not urls:
            tokens = text.strip().split()
            for token in tokens:
                clean_tok = token.strip('\'"(),.<>')
                if self.naked_domain_pattern.match(clean_tok):
                    urls.append(f"https://{clean_tok}")

        return urls

    def extract_domain(self, url):
        """Extract domain from URL"""
        try:
            if not url.startswith("http://") and not url.startswith("https://"):
                url = "https://" + url
            parsed = urlparse(url)
            domain = parsed.netloc or parsed.path.split('/')[0]
            if ':' in domain:
                domain = domain.split(':')[0]
            return domain.lower()
        except:
            return ""

    def preprocess(self, text, anchor_text=None, page_url=None):
        """Main preprocessing function with optional link context"""
        cleaned_text = self.clean_text(text)
        urls = self.extract_urls(cleaned_text)
        domains = [self.extract_domain(url) for url in urls]

        return {
            'cleaned_text': cleaned_text,
            'urls': urls,
            'domains': domains,
            'has_urls': len(urls) > 0,
            'text_length': len(cleaned_text),
            'anchor_text': (anchor_text or "").strip(),
            'page_url': (page_url or "").strip()
        }