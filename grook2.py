import os
from openai import OpenAI

# 1. Configure a chave CORRETAMENTE (note o nome da variável)
os.environ["OPENAI_API_KEY"] = "xai-ay2cNXFlUnVuCRMpFzgOE57ndqQt74TrzI8MNfOTMu8VoPLuQDWO6UelCrhnQ2Pq2qPzroOaTvzKcQoP"

# 2. Crie o cliente
client = OpenAI(
    api_key=os.getenv("OPENAI_API_KEY"),  # Agora vai encontrar a chave
    base_url="https://api.x.ai/v1"
)

# 3. Faça a chamada
try:
    completion = client.chat.completions.create(
        model="grok-3-mini-beta",
        messages=[
            {"role": "system", "content": "You are Grok, a helpful AI."},
            {"role": "user", "content": "Explain quantum computing in simple terms"}
        ]
    )
    print(completion.choices[0].message.content)
except Exception as e:
    print(f"Erro: {e}")