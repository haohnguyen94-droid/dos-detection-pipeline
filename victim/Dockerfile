FROM nginx:1.25-alpine

# TODO (Alpha): install tcpdump, configure entrypoint
# RUN apk add --no-cache tcpdump bash

WORKDIR /victim
COPY . .

# Placeholder — replaced at Alpha milestone
CMD ["nginx", "-g", "daemon off;"]
