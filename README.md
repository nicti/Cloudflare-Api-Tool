# Cloudflare-Api-Tool
## Installation
1) Checkout this repo using:
```bash
git clone https://github.com/nicti/Cloudflare-Api-Tool.git
```
2) Install the composer dependencies using:
```bash
cd Cloudflare-Api-Tool
composer install
```
## Usage
### Firewall Update
```bash
bin/console cloudflare:firewall:update <config>
```
You can find an example configuration [here](https://github.com/nicti/Cloudflare-Api-Tool/blob/main/example/cf:fw:up.config.yaml).