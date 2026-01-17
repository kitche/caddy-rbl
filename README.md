# caddy-rbl ![License](https://img.shields.io/github/license/kitche/caddy-rbl) 

**caddy-rbl** integrates Real time block lists with [Caddy](https://caddyserver.com/). 

---

## Features

- Easy configuration with Caddyfile or JSON
- Detailed logging for security auditing

---



## Installation



```bash
git clone https://github.com/kitche/caddy-rbl.git
cd caddy-rbl
xcaddy build --with github.com/kitche/caddy-modsecurity=/path/to/checkout
```

## Configuration
Example Caddyfile
```bash
example.com {
    rbl {
        lists zen.spamhaus.org bl.spamcop.net
        block_message "Your IP is listed in our blocklist"
        status_code 403
    }
    
    reverse_proxy localhost:8080
}
```




## Contributing

We welcome contributions!

Fork the repository

Create a branch: git checkout -b feature-name

Commit your changes: git commit -m "Add feature"

Push to your branch: git push origin feature-name

Open a Pull Request

