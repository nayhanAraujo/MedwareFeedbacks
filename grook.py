from xai_sdk.v1 import Client
import os
import asyncio  # Adicionado para lidar com chamadas assíncronas

# Configure sua chave
os.environ["XAI_API_KEY"] = "xai-KkdkRilsBlwHKiys9jwGbixCr71ukWDX6XKOBmvNqsEOpCBwBnIu38Y9Sk5FKDLKBIxjHan9lBaQqrLj"

async def test_api():
    try:
        client = Client()
        
        # Chat básico (agora é assíncrono)
        response = await client.chat("Explique quantum computing em 2 frases")
        print("✅ Resposta do chat:", response)
        
        # Listar modelos (se disponível)
        if hasattr(client, 'list_models'):
            models = await client.list_models()
            print("📊 Modelos disponíveis:", models)
        
    except Exception as e:
        print("❌ Erro:", e)

# Executa a função assíncrona
asyncio.run(test_api())