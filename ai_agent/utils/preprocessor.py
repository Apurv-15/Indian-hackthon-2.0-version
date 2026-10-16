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

    def unwrap_redirect_url(self, url):
        """Unwrap redirect parameters from search engines and tracking services."""
        if not url:
            return ""
        try:
            from urllib.parse import parse_qs, unquote
            temp_url = url if (url.startswith("http://") or url.startswith("https://")) else "https://" + url
            parsed = urlparse(temp_url)
            host = (parsed.netloc or '').lower()
            if ':' in host:
                host = host.split(':')[0]
            
            # Common redirect wrapper domains (Google search, Bing, ad services)
            redirect_hosts = {
                'google.com', 'google.co.in', 'bing.com', 'duckduckgo.com',
                'googleadservices.com', 'google.de', 'google.co.uk'
            }
            if any(host == rh or host.endswith('.' + rh) for rh in redirect_hosts):
                qs = parse_qs(parsed.query)
                # Google / Bing redirect params: q, url, u, dest, adurl
                for param in ['q', 'url', 'u', 'dest', 'adurl', 'target']:
                    if param in qs and qs[param]:
                        target = qs[param][0]
                        if target.startswith('http://') or target.startswith('https://'):
                            return target
                        elif target.startswith('//'):
                            return 'https:' + target
                        decoded = unquote(target)
                        if decoded.startswith('http://') or decoded.startswith('https://'):
                            return decoded
        except Exception:
            pass
        return url

    def extract_domain(self, url):
        """Extract domain from URL, unwrapping redirects first if applicable"""
        try:
            url = self.unwrap_redirect_url(url)
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
        unwrapped_urls = [self.unwrap_redirect_url(u) for u in urls]
        effective_urls = unwrapped_urls if unwrapped_urls else urls
        domains = [self.extract_domain(url) for url in effective_urls]

        return {
            'cleaned_text': cleaned_text,
            'urls': effective_urls,
            'raw_urls': urls,
            'domains': domains,
            'has_urls': len(effective_urls) > 0,
            'text_length': len(cleaned_text),
            'anchor_text': (anchor_text or "").strip(),
            'page_url': (page_url or "").strip()
        }