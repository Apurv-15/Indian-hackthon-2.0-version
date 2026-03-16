import re
from urllib.parse import urlparse

class TextPreprocessor:
    def __init__(self):
        pass
    
    def clean_text(self, text):
        """Basic text cleaning"""
        text = ' '.join(text.split())
        return text
    
    def extract_urls(self, text):
        """Extract URLs from text"""
        url_pattern = r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'
        urls = re.findall(url_pattern, text)
        return urls
    
    def extract_domain(self, url):
        """Extract domain from URL"""
        try:
            parsed = urlparse(url)
            domain = parsed.netloc or parsed.path.split('/')[0]
            return domain
        except:
            return ""
    
    def preprocess(self, text):
        """Main preprocessing function"""
        cleaned_text = self.clean_text(text)
        urls = self.extract_urls(cleaned_text)
        domains = [self.extract_domain(url) for url in urls]
        
        return {
            'cleaned_text': cleaned_text,
            'urls': urls,
            'domains': domains,
            'has_urls': len(urls) > 0,
            'text_length': len(cleaned_text)
        }