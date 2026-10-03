# Ollama with the judge model baked in, served by Vertex AI on an L4 GPU.
# Baking the weights in means a replica start loads from the image instead of
# pulling ~5 GB at boot. Vertex routes /api/generate (predict) and / (health)
# here; see infra/judge.tf.
FROM ollama/ollama:latest

ARG MODEL=llama3.1:8b
ENV MODEL=$MODEL \
    OLLAMA_HOST=0.0.0.0:8080 \
    OLLAMA_MODELS=/models \
    OLLAMA_KEEP_ALIVE=-1 \
    OLLAMA_NUM_PARALLEL=4

RUN ollama serve & sleep 5 && ollama pull "$MODEL" && kill %1

COPY entrypoint.sh /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]
