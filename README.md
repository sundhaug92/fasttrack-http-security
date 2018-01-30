# Fasttrack HTTP security

Automatically generate a basic Content-Security-Policy (CSP), as well as relevant SubResource Integrity (SRI) digests

```bash
   mitmdump -v -s interceptor.py # Start mitmdump proxy
   # Open your favorite browser and configure it to use the proxy (should be at localhost:8080, if the browser is running on the same machine as the proxy)
   # Go to mitm.it and follow the instructions to get install the root certificate into the browser, which is needed for HTTPS
   # Start browsing to the target domain(s), fasttrack-http-security will automatically track patterns needed for the basic CSP, as well as registering SRI digests. 
```

```bash
   python3 export-meta.py <domain> [domain2] # Output CSPs and SRIs for the given domains. Alternatively use * as a domain return all CSPs and SRIs (remember to escape *)
```
