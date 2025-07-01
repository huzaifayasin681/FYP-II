# xss_scanner/setup_presentation.py
"""Setup script to create test files for presentation."""

import json
import os
from pathlib import Path

def create_test_files():
    """Create all necessary test files for the presentation."""
    
    print("Setting up test files for XSS Scanner presentation...")
    
    # 1. Create custom payloads file
    custom_payloads = [
        # Basic XSS
        '<script>alert("XSS")</script>',
        '<img src=x onerror=alert(1)>',
        '<svg onload=alert(1)>',
        
        # Breaking out of attributes
        '"><script>alert(1)</script>',
        "';alert(1);//",
        
        # Filter bypass
        '<ScRiPt>alert(1)</ScRiPt>',
        '<script>alert`1`</script>',
        
        # Event handlers
        '<body onload=alert(1)>',
        '<input onfocus=alert(1) autofocus>',
        
        # Advanced
        'javascript:alert(1)',
        '${alert(1)}',
        '{{constructor.constructor("alert(1)")()}}',
    ]
    
    with open('custom_payloads.txt', 'w') as f:
        for payload in custom_payloads:
            f.write(payload + '\n')
    print("✓ Created custom_payloads.txt")
    
    # 2. Create authentication configs
    auth_configs = {
        'form_auth.json': {
            "type": "form",
            "login_url": "http://testphp.vulnweb.com/login.php",
            "username": "test",
            "password": "test",
            "username_field": "uname",
            "password_field": "pass",
            "success_indicator": "logout"
        },
        'token_auth.json': {
            "type": "token",
            "auth_url": "http://api.example.com/v1/",
            "token": "your-api-token-here",
            "header_name": "Authorization",
            "header_format": "Bearer {token}"
        },
        'jwt_auth.json': {
            "type": "jwt",
            "auth_url": "http://api.example.com",
            "username": "admin",
            "password": "password",
            "login_endpoint": "/auth/login",
            "token_field": "access_token"
        }
    }
    
    for filename, config in auth_configs.items():
        with open(filename, 'w') as f:
            json.dump(config, f, indent=2)
        print(f"✓ Created {filename}")
    
    # 3. Create test URLs file
    test_urls = [
        "http://testphp.vulnweb.com/search.php?test=query",
        "http://testphp.vulnweb.com/listproducts.php?cat=1",
        "http://testphp.vulnweb.com/artists.php?artist=1",
        "http://testphp.vulnweb.com/guestbook.php",
        "http://testphp.vulnweb.com/AJAX/index.php",
    ]
    
    with open('test_urls.txt', 'w') as f:
        for url in test_urls:
            f.write(url + '\n')
    print("✓ Created test_urls.txt")
    
    # 4. Create test forms file
    test_forms = [
        {
            "url": "http://testphp.vulnweb.com/search.php",
            "action": "http://testphp.vulnweb.com/search.php",
            "method": "GET",
            "inputs": [
                {"name": "searchFor", "type": "text", "value": ""},
                {"name": "goButton", "type": "submit", "value": "go"}
            ]
        },
        {
            "url": "http://testphp.vulnweb.com/guestbook.php",
            "action": "http://testphp.vulnweb.com/guestbook.php",
            "method": "POST",
            "inputs": [
                {"name": "name", "type": "text", "value": ""},
                {"name": "comment", "type": "textarea", "value": ""}
            ]
        }
    ]
    
    with open('test_forms.json', 'w') as f:
        json.dump(test_forms, f, indent=2)
    print("✓ Created test_forms.json")
    
    # 5. Create demo directories
    dirs = ['reports', 'demo_reports', 'logs']
    for dir_name in dirs:
        Path(dir_name).mkdir(exist_ok=True)
    print("✓ Created output directories")
    
    # 6. Create a simple vulnerable HTML file for local testing
    vulnerable_html = '''<!DOCTYPE html>
<html>
<head>
    <title>XSS Test Page</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; }
        .container { max-width: 600px; margin: 0 auto; }
        .result { background: #f0f0f0; padding: 10px; margin: 20px 0; }
    </style>
</head>
<body>
    <div class="container">
        <h1>XSS Test Page</h1>
        <p>This is a vulnerable page for testing XSS Scanner.</p>
        
        <h2>Search Form (Reflected XSS)</h2>
        <form method="GET">
            <input type="text" name="q" placeholder="Search...">
            <button type="submit">Search</button>
        </form>
        
        <div class="result">
            <?php if(isset($_GET['q'])): ?>
                Search results for: <?php echo $_GET['q']; ?>
            <?php endif; ?>
        </div>
        
        <h2>Comment Form (Potential Stored XSS)</h2>
        <form method="POST">
            <input type="text" name="name" placeholder="Your name"><br><br>
            <textarea name="comment" placeholder="Your comment"></textarea><br><br>
            <button type="submit">Submit</button>
        </form>
    </div>
</body>
</html>'''
    
    with open('test_vulnerable.html', 'w') as f:
        f.write(vulnerable_html)
    print("✓ Created test_vulnerable.html (for local testing)")
    
    print("\n✅ All test files created successfully!")
    print("\nYou can now run:")
    print("  1. python cli/main.py scan --target http://testphp.vulnweb.com/search.php?test=query")
    print("  2. python cli/main.py scan --urls-file test_urls.txt --payloads custom_payloads.txt")
    print("  3. python cli/main.py scan --target <url> --login-config form_auth.json")
    print("  4. python demo_presentation.py --demo")


if __name__ == "__main__":
    create_test_files()