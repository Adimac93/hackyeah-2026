# Ollama with the model baked in, for Cloud Run with an NVIDIA L4.
#
# Pulling at build time rather than on start keeps a cold start to "load
# weights into the GPU" instead of "download 5 GB, then load". See
# docs/DEPLOY.md, "The model host".
FROM ollama/ollama:latest

# Cloud Run sends traffic to 8080. Keep the model resident: unloading it after
# the default five idle minutes would make the next judge call pay the load.
ENV OLLAMA_HOST=0.0.0.0:8080 \
    OLLAMA_MODELS=/models \
    OLLAMA_KEEP_ALIVE=-1

# Must match SEMANTIC_MODEL on the gateway and an entry in the catalog's
# [models] allowed list.
ARG MODEL=llama3.1:8b
RUN ollama serve & \
    for i in $(seq 1 30); do ollama list >/dev/null 2>&1 && break; sleep 1; done && \
    ollama pull "$MODEL"

ENTRYPOINT ["ollama", "serve"]
