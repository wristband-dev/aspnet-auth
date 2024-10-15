To keep configuration changes to a minimum when switching from local development to production,
this sample assumes you are using a free cloudflare tunnel to access your local development server
via a publicly accessible URL with a valid SSL certificate (provided automatically by cloudflare).

NOTE: If you are new to cloudflare tunnels, the following blog post has some additional details on 
setting up cloudflare tunnels https://learnaws.io/blog/cloudflare-tunnel

## Create a Cloudflare CNAME to your developer machine for non-localhost testing of a wristband application (which allows you to set the "Production" flag on your wristband application when creating the application)

- Setup a domain on Cloudflare
    - Create a [free account](https://dash.cloudflare.com/sign-up) on Cloudflare
    - Create and [setup your website DNS](https://developers.cloudflare.com/fundamentals/setup/account-setup/add-site/)
    - Update your [nameservers](https://developers.cloudflare.com/dns/zone-setups/full-setup/setup/#update-your-nameservers) to point to Cloudflare

- Login to the cloudflared cli on your local machine via `cloudflared tunnel login`
- Create a tunnel that will be managed on your local machine
```
cloudflared tunnel create mytunnelname
```
- Assign a subdomain to your tunnel. Note that you can have multiple subdomains that point at the public end of your tunnel.
```
cloudflare tunnel route dns mytunnelname mysubdomainname
```
- list your available tunnels via `cloudflared tunnel list`
- Create a `~/.cloudflared/config.yml` file containing the tunnel identifier and correct port number for your localhost service. NOTE: in our example we are using a http endpoint which we currently have running on 6001 instead of our locah https endpoint which we currently have running on 7001. NOTE ALSO: You can add additional CNAMES and that connect to additional local services by adding additional `- hostname:` and `  service` pairs.
```
tunnel: your-tunnel-uuid
credentials-file: /Users/whatever/.cloudflared/your-tunnel-uuid.json

ingress:

# define hostname matching 
  - hostname: mysubdomain.mydomain.com
    # proxy request to localhost:6001
    service: http://localhost:6001
    # if nothing is matched return 404
  - service: http_status:404
```

- Either run the tunnel temporarily or as a service
    - temporarily
  ```bash
  cloudflared tunnel run
  ```
    - as a service
  ```bash
  sudo cloudflared --config ~/.cloudflared/config.yml service install
  ```
