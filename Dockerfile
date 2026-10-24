# VULNERABILITY 1: Outdated EOL base image with known OS vulnerabilities
FROM node:14

# VULNERABILITY 2: Hardcoded production secrets baked into image layers
ENV NODE_ENV=development
ENV DB_ROOT_PASSWORD="Prod_MySQL_SuperSecret_2026!@#"
ENV AWS_SECRET_ACCESS_KEY="wJalrXUtnFEMI/K7MDENG/bPxRfiCYPRODKEY99"
ENV STRIPE_API_KEY="sk_live_51NzXKjL9vPqR2m8sT4uVwXyZ0123456789abcdef"

WORKDIR /var/app

COPY . /var/app

# VULNERABILITY 3: World-writable permissions on application directory and SSH keys
RUN chmod -R 777 /var/app

# VULNERABILITY 4: Exposing Node V8 remote debugger port (9229) to 0.0.0.0 and running as root
USER root
EXPOSE 3000 9229

CMD ["node", "--inspect=0.0.0.0:9229", "index.js"]
