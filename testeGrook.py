import os
from openai import OpenAI
from dotenv import load_dotenv

# Carregar variáveis de ambiente
load_dotenv()

# Obter a chave da API
XAI_API_KEY = os.getenv('XAI_API_KEY')
if not XAI_API_KEY:
    raise ValueError("XAI_API_KEY não configurada no ambiente.")

# Inicializar o cliente
client = OpenAI(base_url="https://api.x.ai/v1", api_key=XAI_API_KEY)

try:
    print("Iniciando chamada à API...")
    completion = client.chat.completions.create(
        model="grok-3-mini-beta",
        messages=[
            {
                "role": "system",
                "content": "You are Grok, a chatbot inspired by the Hitchhikers Guide to the Galaxy.",
            },
            {
                "role": "user",
                "content": "What is the meaning of life, the universe, and everything?",
            },
        ],
    )
    print("Chamada à API concluída.")
    
    # Imprimir a resposta completa para inspeção
    print("Resposta completa:", completion)
    
    # Verificar e exibir informações de uso, se disponíveis
    if completion.usage:
        print("Informações de uso:", completion.usage.to_json())
    else:
        print("Nenhuma informação de uso retornada.")
    
    # Exibir o conteúdo da resposta
    if completion.choices and len(completion.choices) > 0:
        print("Resposta do modelo:", completion.choices[0].message.content)
    else:
        print("Nenhuma escolha retornada na resposta.")
        
except Exception as e:
    print(f"Erro ao chamar a API: {e}")