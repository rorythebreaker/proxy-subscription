# Free SOCKS5 subscription

Automated SOCKS5 proxy aggregation and verification from Proxifly and Monosans.

**Subscription:** https://rorythebreaker.github.io/proxy-subscription/public/proxies.txt

**Status:** https://rorythebreaker.github.io/proxy-subscription/public/status.json

GitHub Actions attempts to refresh every 5 minutes (at :02, :07, :12...). GitHub does **not** guarantee scheduled start times. Proxies are tested using an HTTPS request to Google's 204 endpoint through SOCKS5. Successful verification from GitHub infrastructure does not guarantee availability from a phone.

Enable repository Settings > Actions > General > Workflow permissions > Read and write permissions; Settings > Pages > Deploy from a branch > main > /(root). Then run Actions > Refresh SOCKS5 proxies > Run workflow.

Public proxies are untrusted. Do not use for sensitive accounts.
